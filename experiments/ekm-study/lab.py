"""Empirical study of TLS channel-binding material in pyOpenSSL.

Everything runs over in-memory BIOs (no sockets, no ports), so it works in
sandboxed environments that forbid local port binding.

Low-level OpenSSL calls (post-handshake auth, renegotiation, session-reused
flag) go through pyOpenSSL's private cffi binding on purpose: pyOpenSSL does
NOT expose a public API for TLS 1.3 post-handshake authentication. Anything
that only works via `OpenSSL._util` is flagged as a boundary in the report.
"""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization

from OpenSSL import SSL, crypto
from OpenSSL._util import ffi as _ffi
from OpenSSL._util import lib as _lib

HERE = pathlib.Path(__file__).resolve().parent

TLS12 = SSL.TLS1_2_VERSION
TLS13 = SSL.TLS1_3_VERSION

# Fixed labels/contexts so every connection can be compared apples-to-apples.
LABEL_LOGIN = b"com.example.login-proof"
LABEL_EXPORTER_RFC9266 = b"EXPORTER-tls-exporter"
LABEL_OTHER = b"com.example.something-else"
CTX_A = b"tenant-42/nonce-abc"
CTX_B = b"tenant-42/nonce-xyz"
EKM_LEN = 32


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def h(value: bytes | None, width: int = 12) -> str:
    if value is None:
        return "None"
    return hashlib.sha256(value).hexdigest()[:width] + f" (len={len(value)})"


def _load(name: str):
    return HERE / name


def _drain(src: SSL.Connection, dst: SSL.Connection) -> bool:
    """Copy all pending records from src's outbound BIO into dst. Return moved?"""
    moved = False
    while True:
        try:
            chunk = src.bio_read(4096)
        except SSL.WantReadError:
            return moved
        dst.bio_write(chunk)
        moved = True


def pump(client: SSL.Connection, server: SSL.Connection, max_rounds: int = 400) -> None:
    """Move bytes between the two built-in memory BIOs until both are quiescent.

    A settling window plus application-read nudges are required for
    post-handshake records: TLS 1.3 NewSessionTicket and post-handshake
    CertificateRequest/Certificate/Finished are only folded into the
    connection's state on a record-layer operation, and can be written a
    round after the handshake reports completion.
    """
    idle = 0
    for _ in range(max_rounds):
        for conn in (client, server):
            try:
                conn.do_handshake()
            except SSL.WantReadError:
                pass
        moved = _drain(client, server) or _drain(server, client)
        # Nudge record-layer processing so post-handshake messages are handled.
        for conn in (client, server):
            try:
                conn.recv(65536)
            except (SSL.WantReadError, SSL.ZeroReturnError):
                pass
        moved = _drain(client, server) or _drain(server, client) or moved
        if moved:
            idle = 0
        else:
            idle += 1
            if idle >= 3:
                return
    raise RuntimeError("pump did not converge")


def new_pair(client_ctx: SSL.Context, server_ctx: SSL.Context):
    client = SSL.Connection(client_ctx, None)
    server = SSL.Connection(server_ctx, None)
    client.set_connect_state()
    server.set_accept_state()
    return client, server


def settle_ticket(client: SSL.Connection, server: SSL.Connection) -> None:
    """Drive TLS 1.3 NewSessionTicket processing.

    In both pyOpenSSL and the stdlib MemoryBIO path, a client does not fold a
    post-handshake NewSessionTicket into its resumable session until it runs a
    record-layer operation (an application-data round trip does this
    deterministically). Without this, get_session() returns a session whose
    ticket field is empty and the next ClientHello omits pre_shared_key.
    """
    token = b"ekm-study-ticket-nudge"
    client.write(token)
    _drain(client, server)
    if server.recv(len(token)) != token:
        raise RuntimeError("ticket nudge round trip failed")
    server.write(token)
    _drain(server, client)
    if client.recv(len(token)) != token:
        raise RuntimeError("ticket nudge round trip failed")
    pump(client, server)


def fresh_handshake(client_ctx: SSL.Context, server_ctx: SSL.Context):
    client, server = new_pair(client_ctx, server_ctx)
    pump(client, server)
    return client, server


def safe_master_key(conn: SSL.Connection) -> bytes | None:
    # OpenSSL 3+ erases the TLS 1.3 master secret after the handshake, so
    # master_key() raises on 1.3. Return None instead of aborting the study.
    try:
        return conn.master_key()
    except SSL.Error:
        return None


def resumed_flag(conn: SSL.Connection) -> int:
    return int(_lib.SSL_session_reused(conn._ssl))


def cert_fp(conn: SSL.Connection, peer: bool = True) -> str | None:
    cert = conn.get_peer_certificate() if peer else conn.get_certificate()
    if cert is None:
        return None
    return cert.to_cryptography().fingerprint(crypto_hashes.SHA256()).hex()[:16]


# --------------------------------------------------------------------------- #
# context factories
# --------------------------------------------------------------------------- #
def _basic_ctx(method: int) -> SSL.Context:
    ctx = SSL.Context(method)
    return ctx


def server_ctx(version: int, *, allow_reneg: bool = False) -> SSL.Context:
    ctx = _basic_ctx(SSL.TLS_METHOD)
    ctx.set_min_proto_version(version)
    ctx.set_max_proto_version(version)
    ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, _load("server.pem").read_bytes()))
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, _load("server.key").read_bytes()))
    # Trust the test CA so client certs verify in PHA/renegotiation.
    ctx.load_verify_locations(_load("ca.pem"))
    ctx.set_verify(SSL.VERIFY_PEER, lambda *a: True)
    # Required so the server accepts session resumption attempts.
    ctx.set_session_id(b"ekm-study")
    if allow_reneg:
        # OpenSSL 3.x/4.x disables renegotiation by default; Context exposes
        # only set_options, so read the mask through the low-level binding.
        opts = _lib.SSL_CTX_get_options(ctx._context)
        ctx.set_options(opts & ~SSL.OP_NO_RENEGOTIATION)
    return ctx


def client_ctx(
    version: int,
    *,
    client_cert: str | None = None,
    post_handshake_auth: bool = False,
    allow_reneg: bool = False,
) -> SSL.Context:
    ctx = _basic_ctx(SSL.TLS_METHOD)
    ctx.set_min_proto_version(version)
    ctx.set_max_proto_version(version)
    ctx.load_verify_locations(_load("ca.pem"))
    ctx.set_verify(SSL.VERIFY_PEER, lambda *a: True)
    if client_cert is not None:
        ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, _load(client_cert + ".pem").read_bytes()))
        ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, _load(client_cert + ".key").read_bytes()))
    if post_handshake_auth:
        # Low-level only: no public pyOpenSSL wrapper exists. The binding
        # exposes it as a void call, so there is no return value to check.
        _lib.SSL_CTX_set_post_handshake_auth(ctx._context, 1)
    if allow_reneg:
        opts = _lib.SSL_CTX_get_options(ctx._context)
        ctx.set_options(opts & ~SSL.OP_NO_RENEGOTIATION)
    return ctx


# --------------------------------------------------------------------------- #
# observation model
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Snapshot:
    name: str
    version: str
    resumed: int
    client_random: str
    master_key: str
    local_finished: str
    peer_finished: str
    ekm_no_ctx: str
    ekm_empty_ctx: str
    ekm_ctx_a: str
    ekm_ctx_b: str
    ekm_other_label: str
    server_cert_fp: str | None
    client_cert_fp: str | None

    @classmethod
    def take(cls, name: str, client: SSL.Connection, server: SSL.Connection) -> "Snapshot":
        # EKM is derived identically on both ends; assert it once here.
        ekm_none = client.export_keying_material(LABEL_LOGIN, EKM_LEN)
        ekm_empty = client.export_keying_material(LABEL_LOGIN, EKM_LEN, b"")
        assert server.export_keying_material(LABEL_LOGIN, EKM_LEN) == ekm_none
        assert server.export_keying_material(LABEL_LOGIN, EKM_LEN, b"") == ekm_empty
        assert client.export_keying_material(LABEL_LOGIN, EKM_LEN, CTX_A) == server.export_keying_material(
            LABEL_LOGIN, EKM_LEN, CTX_A
        )
        return cls(
            name=name,
            version=client.get_protocol_version_name(),
            resumed=resumed_flag(client),
            client_random=h(client.client_random()),
            master_key=h(safe_master_key(client)),
            local_finished=h(client.get_finished()),
            peer_finished=h(client.get_peer_finished()),
            ekm_no_ctx=h(ekm_none),
            ekm_empty_ctx=h(ekm_empty),
            ekm_ctx_a=h(client.export_keying_material(LABEL_LOGIN, EKM_LEN, CTX_A)),
            ekm_ctx_b=h(client.export_keying_material(LABEL_LOGIN, EKM_LEN, CTX_B)),
            ekm_other_label=h(client.export_keying_material(LABEL_OTHER, EKM_LEN)),
            server_cert_fp=cert_fp(client),
            client_cert_fp=cert_fp(server),
        )


def tls_server_end_point(client: SSL.Connection) -> str:
    """RFC 5929 tls-server-end-point: hash of the server certificate's SPKI."""
    spki = client.get_peer_certificate().to_cryptography().public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()[:16]


def tls_exporter_rfc9266(conn: SSL.Connection) -> bytes:
    # RFC 9266: label "EXPORTER-tls-exporter", length 32, no context for the
    # base (non-client-auth) channel binding.
    return conn.export_keying_material(LABEL_EXPORTER_RFC9266, 32)
