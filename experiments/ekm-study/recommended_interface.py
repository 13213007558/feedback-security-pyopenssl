"""Reference interface for binding an application login proof to the TLS channel.

Design rule demonstrated here:
  * channel possession  -> proves "the presenter holds THIS TLS connection"
  * user authorization  -> proves "the presenter is user U" (an app token)
The two are combined by the application, never conflated.

Everything used below is public pyOpenSSL except where explicitly marked
"LOW-LEVEL / experimental". No socket is required: the logic only needs an
established SSL.Connection.
"""
from __future__ import annotations

import hmac
import hashlib

from OpenSSL import SSL

# Pick ONE private, application-specific label and freeze it. Reusing another
# protocol's label (e.g. an RFC-registered EXPORTER-* name) would mix domains.
LOGIN_LABEL = b"com.example.login-channel-binding-v1"
EKM_LEN = 32


class ChannelBinding:
    """Per-connection channel-possession material. Never a long-term identity."""

    def __init__(self, conn: SSL.Connection, tenant_nonce: bytes):
        # The context is application-chosen, so both endpoints can agree on it
        # out of band. Bind the challenge/nonce and the logical target here.
        self._context = tenant_nonce
        self._ekm = conn.export_keying_material(LOGIN_LABEL, EKM_LEN, self._context)
        # The certificate identity is independent of the per-connection secret.
        peer = conn.get_peer_certificate()
        self.peer_spki_fp = self._spki_sha256(peer) if peer is not None else None
        self.protocol = conn.get_protocol_version_name()

    @staticmethod
    def _spki_sha256(cert) -> str:
        from cryptography.hazmat.primitives import serialization

        spki = cert.to_cryptography().public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(spki).hexdigest()

    def make_proof(self, challenge: bytes) -> bytes:
        """Return the value that may cross the wire: a keyed tag, never the EKM."""
        return hmac.new(self._ekm, challenge, hashlib.sha256).digest()

    def expected_proof(self, challenge: bytes) -> bytes:
        """Server-side: recompute the tag from its own identical EKM."""
        return self.make_proof(challenge)


def verify_login(
    conn: SSL.Connection,
    tenant_nonce: bytes,
    challenge: bytes,
    presented_tag: bytes,
    authorization_token: str,
    authorize_user,
) -> dict:
    """Full login check on the server side.

    :param authorize_user: callable(token) -> user id; encapsulates the
        user-authorization layer that is independent of TLS.
    :raises PermissionError: on channel or authorization failure.
    """
    binding = ChannelBinding(conn, tenant_nonce)
    expected = binding.expected_proof(challenge)

    # 1) Channel possession: constant-time tag comparison. A holder of any
    #    other connection derives a different EKM and cannot forge this.
    if not hmac.compare_digest(expected, presented_tag):
        raise PermissionError("channel possession proof does not match this connection")

    # 2) User authorization: separate trust decision over the app token.
    user_id = authorize_user(authorization_token)

    # 3) The certificate identity is the only stable, long-lived handle and is
    #    recorded for audit; it is NOT derived from the EKM/Finished.
    return {
        "user_id": user_id,
        "protocol": binding.protocol,
        "peer_spki_fp": binding.peer_spki_fp,
        "bound_to_connection": True,
    }


# --------------------------------------------------------------------------- #
# Post-handshake authentication (TLS 1.3) - SUPPORT BOUNDARY
# --------------------------------------------------------------------------- #
def enable_client_post_handshake_auth(ctx: SSL.Context) -> None:
    """Opt a client context into answering post-handshake CertificateRequests.

    BOUNDARY: pyOpenSSL has no public API for this. It only works through the
    private cffi binding and is therefore not portable across pyOpenSSL
    versions. The server-side trigger (SSL_verify_client_post_handshake) and
    SSL_VERIFY_POST_HANDSHAKE are likewise private. On TLS 1.2 the equivalent
    is renegotiation, which OpenSSL 4.0 restricts heavily.
    """
    from OpenSSL._util import lib as _lib

    _lib.SSL_CTX_set_post_handshake_auth(ctx._context, 1)


# --------------------------------------------------------------------------- #
# What each material can and cannot prove
# --------------------------------------------------------------------------- #
MATERIAL_SEMANTICS = {
    "export_keying_material": {
        "proves": "holder of the live connection's exporter secret on this exact association",
        "scope": "this connection/handshake only; rotates on resumption and renegotiation",
        "long_term_identity": False,
        "share_raw_value": False,  # present an HMAC tag instead
    },
    "get_finished / get_peer_finished": {
        "proves": "transcript-integrity value (Finished verify_data) for a handshake",
        "scope": "TLS1.3 client value is overwritten by each PHA; tls-unique is fragile under resumption",
        "long_term_identity": False,
        "share_raw_value": False,
    },
    "certificate / SPKI (tls-server-end-point)": {
        "proves": "the authenticated certificate identity (subject public key)",
        "scope": "stable across resumption and re-key until the certificate rotates",
        "long_term_identity": True,
        "share_raw_value": True,  # a hash/fingerprint is safe to log and compare
    },
}
