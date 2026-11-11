"""
Secure client-side configuration sample for *requiring* OCSP stapling
with pyOpenSSL.

Policy goal
-----------
A connection may only be treated as verified by the application when ALL
of the following hold for the *current* handshake:

1. the TLS handshake completed under ``VERIFY_PEER`` against the
   configured trust store (certificate chain valid), and
2. the client actually sent the ``status_request`` extension
   (``Connection.request_ocsp()``), and
3. the server stapled a non-empty OCSP response, and
4. the application-supplied validator accepted that response.

A successful handshake alone is NEVER sufficient evidence: if the client
forgets to call ``request_ocsp()``, or a TLS 1.2 session is resumed, the
OpenSSL client callback does not fire at all and the handshake still
succeeds.

What a PRODUCTION validator must check
--------------------------------------
pyOpenSSL hands the raw DER bytes of the stapled ``OCSPResponse`` to the
callback and nothing more.  A production validator must parse them (e.g.
with ``cryptography.x509.ocsp.load_der_ocsp_response``) and verify, at
minimum:

* ``response_status`` is ``SUCCESSFUL`` (not unauthorized/try-later/...);
* the embedded ``SingleResponse`` has ``certificate_status == GOOD``
  (reject ``REVOKED`` and, under a hard-fail policy, ``UNKNOWN``);
* the ``certID`` matches the peer certificate: same ``serial_number``
  and issuer name/key hashes computed with the indicated hash algorithm
  against the actual issuer certificate;
* the response signature verifies under the responder certificate, and
  the responder is either the issuing CA itself or a delegated responder
  whose certificate chains to the CA and carries the
  ``id-kp-OCSPSigning`` extended key usage;
* freshness: ``this_update`` (and ``next_update`` when present) bracket
  the current time within an accepted skew/lifetime window;
* the nonce, if the client sent one (pyOpenSSL does not add one; see
  limitations in COVERAGE.md).

Concurrency note
----------------
One ``OCSPStaplingPolicy`` instance tracks exactly one connection.
``StaplingClientContext.open_connection`` creates a fresh policy per
connection and the context-level dispatcher routes callbacks to the
right policy; a connection without a registered policy fails closed.
"""

from OpenSSL.SSL import (
    VERIFY_PEER,
    Context,
    Connection,
    TLS_METHOD,
    TLS1_2_VERSION,
)

__all__ = [
    "OCSPStaplingPolicy",
    "StaplingClientContext",
]


class OCSPStaplingPolicy:
    """
    Enforcing client-side OCSP stapling policy for one connection.

    ``client_callback`` hard-fails the handshake (returns ``False``)
    whenever the server does not staple a response or the validator
    rejects it.  ``is_verified`` is the defense-in-depth check the
    application must consult after the handshake, because there are
    paths (no ``request_ocsp()``, TLS 1.2 resumption) where OpenSSL
    never invokes the callback at all.
    """

    def __init__(self, validator):
        """
        :param validator: callable ``(connection, der_bytes) -> bool``
            deciding whether a stapled OCSP response is acceptable.
        """
        self._validator = validator
        self.reset()

    def reset(self):
        self.handshake_completed = False
        self.callback_invocations = 0
        self.empty_signals = 0
        self.accepted_responses = []

    def client_callback(self, connection, ocsp_data, data):
        self.callback_invocations += 1
        if not ocsp_data:
            # Server stapled nothing (or TLS 1.3 resumption).
            self.empty_signals += 1
            return False
        if not self._validator(connection, ocsp_data):
            return False
        self.accepted_responses.append(bytes(ocsp_data))
        return True

    def is_verified(self):
        """
        May the application treat this connection as verified?

        Requires a completed handshake AND at least one stapled response
        accepted by the validator during THIS handshake.
        """
        return self.handshake_completed and bool(self.accepted_responses)


class StaplingClientContext:
    """
    Client ``Context`` wrapper with secure defaults for a
    stapling-required deployment.

    The caller remains responsible for hostname verification after the
    handshake (pyOpenSSL does not perform it); use SNI via
    ``Connection.set_tlsext_host_name`` where applicable.
    """

    def __init__(self, trust_store_certs, min_proto_version=TLS1_2_VERSION):
        """
        :param trust_store_certs: iterable of trusted root
            ``OpenSSL.crypto.X509`` certificates.
        """
        self._policies = {}
        self.context = Context(TLS_METHOD)
        self.context.set_min_proto_version(min_proto_version)
        store = self.context.get_cert_store()
        for cert in trust_store_certs:
            store.add_cert(cert)
        # Chain verification failure aborts the handshake.
        self.context.set_verify(VERIFY_PEER)
        self.context.set_ocsp_client_callback(self._dispatch, None)

    def _dispatch(self, connection, ocsp_data, data):
        policy = self._policies.get(connection)
        if policy is None:
            # No policy registered for this connection: fail closed.
            return False
        return policy.client_callback(connection, ocsp_data, data)

    def open_connection(self, validator, request_ocsp=True):
        """
        Create a client ``Connection`` plus its fresh
        ``OCSPStaplingPolicy``.  The connection asks the server for a
        stapled OCSP response unless ``request_ocsp`` is false (test
        hook for the "client forgot to ask" regression).

        After driving the handshake to completion, set
        ``policy.handshake_completed = True`` and consult
        ``policy.is_verified()`` before exchanging application data.
        """
        policy = OCSPStaplingPolicy(validator)
        conn = Connection(self.context)
        self._policies[conn] = policy
        if request_ocsp:
            conn.request_ocsp()
        conn.set_connect_state()
        return conn, policy
