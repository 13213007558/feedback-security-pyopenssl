"""
Regression suite: a client policy that *requires* OCSP stapling must
never let a connection be treated as verified when the stapled response
is missing, empty, rejected, or when the certificate chain fails.

All handshakes run over memory BIOs.  OCSP responses are prebuilt with
``cryptography`` and stapled verbatim; their *content* is validated by a
controlled validator (see ``make_validator``) standing in for the
production checks listed in ``secure_client_config.py``.

Recorded facts (asserted below, summarized in COVERAGE.md):

* TLS 1.2 full handshake: client callback fires with stapled bytes.
* TLS 1.2 resumed session: client callback NEVER fires, yet the
  handshake succeeds -- handshake success is not revocation evidence.
* TLS 1.3 full handshake: client callback fires with stapled bytes.
* TLS 1.3 resumed session: client callback fires with b"" -- "callback
  fired" alone is not evidence either; the payload must be non-empty.
* Chain verification failure: handshake aborts before the OCSP client
  callback runs (0 invocations).
"""

import datetime
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPResponderEncoding,
    OCSPResponseBuilder,
    OCSPResponseStatus,
    load_der_ocsp_response,
)
from OpenSSL.crypto import FILETYPE_ASN1, load_certificate
from OpenSSL.SSL import (
    TLS1_2_VERSION,
    TLS1_3_VERSION,
    Connection,
    Context,
    Error as SSLError,
    TLS_METHOD,
    WantReadError,
)
sys.path.insert(0, str(Path(__file__).parent))

from secure_client_config import StaplingClientContext  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)
TLS_VERSIONS = [
    pytest.param(TLS1_2_VERSION, id="TLS1.2"),
    pytest.param(TLS1_3_VERSION, id="TLS1.3"),
]


# ---------------------------------------------------------------------
# Fixtures: CA / server certificates and prebuilt OCSP responses
# ---------------------------------------------------------------------


def _make_ca(common_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                         common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_server_cert(ca_key, ca_cert):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                         "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _build_ocsp_response(server_cert, ca_cert, ca_key, cert_status):
    if cert_status == OCSPCertStatus.REVOKED:
        revocation_time = NOW - datetime.timedelta(hours=1)
        revocation_reason = x509.ReasonFlags.key_compromise
    else:
        revocation_time = None
        revocation_reason = None
    builder = (
        OCSPResponseBuilder()
        .add_response(
            cert=server_cert,
            issuer=ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=NOW - datetime.timedelta(hours=1),
            next_update=NOW + datetime.timedelta(hours=24),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(OCSPResponderEncoding.HASH, ca_cert)
    )
    response = builder.sign(ca_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="session")
def pki():
    ca_key, ca_cert = _make_ca("Test Root CA")
    stranger_key, stranger_cert = _make_ca("Stranger Root CA")
    server_key, server_cert = _make_server_cert(ca_key, ca_cert)
    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "stranger_cert": stranger_cert,
        "server_key": server_key,
        "server_cert": server_cert,
        "good_ocsp": _build_ocsp_response(
            server_cert, ca_cert, ca_key, OCSPCertStatus.GOOD
        ),
        "revoked_ocsp": _build_ocsp_response(
            server_cert, ca_cert, ca_key, OCSPCertStatus.REVOKED
        ),
    }


def _to_pyopenssl(cert):
    # X509Store.add_cert still requires pyOpenSSL X509 objects.
    der = cert.public_bytes(serialization.Encoding.DER)
    return load_certificate(FILETYPE_ASN1, der)


# ---------------------------------------------------------------------
# Controlled validator (test double for the production checks)
# ---------------------------------------------------------------------


def make_validator(pki, allowed_serial=None):
    """
    Controlled validator: parses the DER OCSP response and checks
    response status, certificate status, serial number, freshness, and
    the responder signature against the test CA.  Returns bool instead
    of raising so the policy can map False to a handshake abort.
    """
    ca_cert = pki["ca_cert"]
    serial = allowed_serial or pki["server_cert"].serial_number

    def validate(connection, der_bytes):
        try:
            response = load_der_ocsp_response(der_bytes)
        except ValueError:
            return False
        if response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return False
        if response.certificate_status != OCSPCertStatus.GOOD:
            return False
        if response.serial_number != serial:
            return False
        if response.this_update_utc > NOW + datetime.timedelta(minutes=5):
            return False
        if response.next_update_utc < NOW - datetime.timedelta(minutes=5):
            return False
        try:
            ca_cert.public_key().verify(
                response.signature,
                response.tbs_response_bytes,
                padding.PKCS1v15(),
                response.signature_hash_algorithm,
            )
        except Exception:
            return False
        return True

    return validate


# ---------------------------------------------------------------------
# Memory-BIO plumbing
# ---------------------------------------------------------------------


def pump(client, server):
    """Shuttle pending bytes between the two memory BIOs."""
    for src, dst in ((client, server), (server, client)):
        while True:
            try:
                data = src.bio_read(65536)
            except WantReadError:
                break
            if not data:
                break
            dst.bio_write(data)


def drive_handshake(client, server):
    """Drive both connections through the handshake over memory BIOs."""
    client.set_connect_state()
    server.set_accept_state()
    pending = [client, server]
    for _ in range(1000):
        still_pending = []
        for conn in pending:
            try:
                conn.do_handshake()
            except WantReadError:
                still_pending.append(conn)
        pump(client, server)
        if not still_pending:
            return
        pending = still_pending
    raise AssertionError("handshake did not converge")


def make_server(pki, ocsp_response, tls_version, ctx_holder=None):
    """
    Build a server connection.  ``ocsp_response`` is the prebuilt DER
    bytes to staple, ``b""`` to staple an empty response, or ``None``
    to not configure OCSP on the server at all.  ``ctx_holder`` receives
    the context so sessions can be resumed against the same cache.
    """
    ctx = Context(TLS_METHOD)
    ctx.set_min_proto_version(tls_version)
    ctx.set_max_proto_version(tls_version)
    ctx.use_privatekey(pki["server_key"])
    ctx.use_certificate(pki["server_cert"])
    if ocsp_response is not None:
        ctx.set_ocsp_server_callback(lambda conn, data: ocsp_response,
                                     None)
    server = Connection(ctx)
    server.set_accept_state()
    if ctx_holder is not None:
        ctx_holder.append(ctx)
    return server


def make_client(pki, tls_version, trust="ca"):
    trusted = pki["ca_cert"] if trust == "ca" else pki["stranger_cert"]
    client_ctx = StaplingClientContext(
        [_to_pyopenssl(trusted)], min_proto_version=tls_version
    )
    client_ctx.context.set_max_proto_version(tls_version)
    return client_ctx


# ---------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------


class TestStaplingRequired:
    @pytest.mark.parametrize("tls_version", TLS_VERSIONS)
    def test_good_response_accepted_and_verified(self, pki, tls_version):
        """Baseline: stapled GOOD response, valid chain -> verified."""
        client_ctx = make_client(pki, tls_version)
        conn, policy = client_ctx.open_connection(
            make_validator(pki)
        )
        server = make_server(pki, pki["good_ocsp"], tls_version)
        drive_handshake(conn, server)
        policy.handshake_completed = True

        assert policy.callback_invocations == 1
        assert policy.accepted_responses == [pki["good_ocsp"]]
        assert policy.is_verified()

    @pytest.mark.parametrize("tls_version", TLS_VERSIONS)
    def test_no_ocsp_request_handshake_succeeds_not_verified(
        self, pki, tls_version
    ):
        """
        Client never calls request_ocsp(): the callback never fires and
        the handshake still succeeds.  Only the policy check keeps the
        application from treating the connection as verified.
        """
        client_ctx = make_client(pki, tls_version)
        conn, policy = client_ctx.open_connection(
            make_validator(pki), request_ocsp=False
        )
        server = make_server(pki, pki["good_ocsp"], tls_version)
        drive_handshake(conn, server)
        policy.handshake_completed = True

        assert policy.callback_invocations == 0
        assert not policy.is_verified()

    @pytest.mark.parametrize("tls_version", TLS_VERSIONS)
    def test_server_without_stapling_aborts(self, pki, tls_version):
        """
        Server has no OCSP configured: OpenSSL reports b"" to the client
        callback, the policy refuses, and the handshake fails.
        """
        client_ctx = make_client(pki, tls_version)
        conn, policy = client_ctx.open_connection(
            make_validator(pki)
        )
        server = make_server(pki, None, tls_version)
        with pytest.raises(SSLError):
            drive_handshake(conn, server)

        assert policy.callback_invocations == 1
        assert policy.empty_signals == 1
        assert not policy.is_verified()

    @pytest.mark.parametrize("tls_version", TLS_VERSIONS)
    def test_server_staples_empty_response_aborts(self, pki, tls_version):
        """Server callback returns b"": same hard failure."""
        client_ctx = make_client(pki, tls_version)
        conn, policy = client_ctx.open_connection(
            make_validator(pki)
        )
        server = make_server(pki, b"", tls_version)
        with pytest.raises(SSLError):
            drive_handshake(conn, server)

        assert policy.callback_invocations == 1
        assert policy.empty_signals == 1
        assert not policy.is_verified()

    @pytest.mark.parametrize("tls_version", TLS_VERSIONS)
    def test_revoked_response_rejected(self, pki, tls_version):
        """Validator rejects a REVOKED response -> handshake fails."""
        client_ctx = make_client(pki, tls_version)
        conn, policy = client_ctx.open_connection(
            make_validator(pki)
        )
        server = make_server(pki, pki["revoked_ocsp"], tls_version)
        with pytest.raises(SSLError):
            drive_handshake(conn, server)

        assert policy.callback_invocations == 1
        assert policy.accepted_responses == []
        assert not policy.is_verified()

    @pytest.mark.parametrize("tls_version", TLS_VERSIONS)
    def test_validator_exception_aborts_handshake(self, pki, tls_version):
        """An exception in the validator propagates to the caller."""

        class ValidatorBoom(Exception):
            pass

        def boom(connection, der_bytes):
            raise ValidatorBoom()

        client_ctx = make_client(pki, tls_version)
        conn, policy = client_ctx.open_connection(boom)
        server = make_server(pki, pki["good_ocsp"], tls_version)
        with pytest.raises(ValidatorBoom):
            drive_handshake(conn, server)

        assert not policy.is_verified()

    @pytest.mark.parametrize("tls_version", TLS_VERSIONS)
    def test_untrusted_chain_fails_despite_good_stapling(
        self, pki, tls_version
    ):
        """
        Client trusts the wrong CA: the handshake aborts on certificate
        verification even though the server staples a valid response.
        OpenSSL never reaches the OCSP client callback (0 invocations).
        """
        client_ctx = make_client(pki, tls_version, trust="stranger")
        conn, policy = client_ctx.open_connection(
            make_validator(pki)
        )
        server = make_server(pki, pki["good_ocsp"], tls_version)
        with pytest.raises(SSLError):
            drive_handshake(conn, server)

        assert policy.callback_invocations == 0
        assert not policy.is_verified()


class TestResumption:
    """
    Resumed sessions carry no fresh revocation evidence.  The policy
    must not treat them as verified -- and the way that plays out
    differs per protocol version, which is exactly why "the handshake
    succeeded" must never be used as a proxy.
    """

    def _run_full_then_resumed(self, pki, tls_version):
        client_ctx = make_client(pki, tls_version)
        server_ctx_holder = []

        # Full handshake: stapled GOOD response, verified.
        conn1, policy1 = client_ctx.open_connection(
            make_validator(pki)
        )
        server1 = make_server(pki, pki["good_ocsp"], tls_version,
                              ctx_holder=server_ctx_holder)
        drive_handshake(conn1, server1)
        policy1.handshake_completed = True
        assert policy1.is_verified()

        # Let TLS 1.3 session tickets reach the client.
        pump(conn1, server1)
        try:
            conn1.recv(1)
        except WantReadError:
            pass
        pump(conn1, server1)
        session = conn1.get_session()
        assert session is not None

        # Resumed connection against the same server context.
        conn2, policy2 = client_ctx.open_connection(
            make_validator(pki)
        )
        conn2.set_session(session)
        server2 = Connection(server_ctx_holder[0])
        server2.set_accept_state()
        return conn2, policy2, server2

    def test_tls12_resumption_succeeds_without_callback(self, pki):
        """
        TLS 1.2 resumption: the OCSP client callback NEVER fires, yet
        the resumed handshake succeeds.  is_verified() is the only
        thing stopping the application from trusting the connection.
        """
        conn2, policy2, server2 = self._run_full_then_resumed(
            pki, TLS1_2_VERSION
        )
        drive_handshake(conn2, server2)
        policy2.handshake_completed = True

        assert policy2.callback_invocations == 0
        assert not policy2.is_verified()

    def test_tls13_resumption_signals_empty_and_aborts(self, pki):
        """
        TLS 1.3 resumption: the client callback fires with b"" (no
        Certificate message, no stapled status), so the enforcing
        policy aborts the resumed handshake outright.
        """
        conn2, policy2, server2 = self._run_full_then_resumed(
            pki, TLS1_3_VERSION
        )
        with pytest.raises(SSLError):
            drive_handshake(conn2, server2)

        assert policy2.callback_invocations == 1
        assert policy2.empty_signals == 1
        assert not policy2.is_verified()
