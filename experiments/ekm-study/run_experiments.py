"""Run the full study and print a structured transcript.

Usage: .venv/bin/python experiments/ekm-study/run_experiments.py
"""
from __future__ import annotations

import hmac
import sys

from OpenSSL import SSL
from OpenSSL._util import ffi as _ffi
from OpenSSL._util import lib as _lib

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import lab  # noqa: E402

LINE = "=" * 78


def title(text: str) -> None:
    print("\n" + LINE)
    print(text)
    print(LINE)


def show(snap: lab.Snapshot) -> None:
    for f in (
        "version", "resumed", "client_random", "master_key",
        "local_finished", "peer_finished", "ekm_no_ctx", "ekm_empty_ctx",
        "ekm_ctx_a", "ekm_ctx_b", "ekm_other_label",
        "server_cert_fp", "client_cert_fp",
    ):
        print(f"  {f:16s} {getattr(snap, f)}")


def fresh_suite(version: int, tag: str) -> None:
    title(f"1. FRESH CONNECTIONS  ({tag})")
    sctx = lab.server_ctx(version)
    cctx = lab.client_ctx(version)
    c1, s1 = lab.fresh_handshake(cctx, sctx)
    c2, s2 = lab.fresh_handshake(cctx, sctx)
    snap1 = lab.Snapshot.take("fresh-1", c1, s1)
    snap2 = lab.Snapshot.take("fresh-2", c2, s2)
    print("-- connection A"); show(snap1)
    print("-- connection B (same certs, same contexts)"); show(snap2)

    ekm = c1.export_keying_material(lab.LABEL_LOGIN, lab.EKM_LEN)
    assert c1.export_keying_material(lab.LABEL_LOGIN, lab.EKM_LEN) == ekm, "EKM must be deterministic"
    mk1 = lab.safe_master_key(c1)
    if mk1 is not None:
        assert ekm != mk1, "EKM must not equal master key"
    assert ekm != c1.get_finished() and ekm != c1.get_peer_finished()
    assert snap1.ekm_no_ctx != snap2.ekm_no_ctx, "EKM rotates per connection"
    assert snap1.client_random != snap2.client_random
    assert snap1.local_finished != snap2.local_finished
    assert snap1.peer_finished != snap2.peer_finished
    assert snap1.server_cert_fp == snap2.server_cert_fp, "cert identity is stable"
    assert lab.tls_server_end_point(c1) == lab.tls_server_end_point(c2)
    assert lab.tls_exporter_rfc9266(c1) == lab.tls_exporter_rfc9266(s1)
    assert lab.tls_exporter_rfc9266(c1) != lab.tls_exporter_rfc9266(c2)

    none_v = c1.export_keying_material(lab.LABEL_LOGIN, lab.EKM_LEN, None)
    empty_v = c1.export_keying_material(lab.LABEL_LOGIN, lab.EKM_LEN, b"")
    if version == lab.TLS12:
        assert none_v != empty_v, "TLS1.2: no-context vs empty-context differ"
        print("  no-context == empty-context? NO  (RFC5705 use_context flag changes PRF input)")
    else:
        assert none_v == empty_v, "TLS1.3: no-context and empty-context coincide"
        print("  no-context == empty-context? YES (RFC8446 always length-prefixes context)")

    k16 = c1.export_keying_material(lab.LABEL_LOGIN, 16)
    k64 = c1.export_keying_material(lab.LABEL_LOGIN, 64)
    if version == lab.TLS12:
        # TLS 1.2 PRF: one expand stream, shorter export is a prefix of longer.
        assert k16 == ekm[:16] and ekm == k64[:32]
        print("  export length: TLS1.2 PRF stream (16B is prefix of 32B/64B)")
    else:
        # RFC 8446: L is part of the HKDF-Expand label, so each length is distinct.
        assert k16 != ekm[:16] and ekm != k64[:32]
        print("  export length: TLS1.3 bakes length into HKDF label (no prefix relation)")
    assert c1.export_keying_material(lab.LABEL_LOGIN, 32, lab.CTX_A) != c1.export_keying_material(
        lab.LABEL_LOGIN, 32, lab.CTX_B
    )
    assert c1.get_peer_finished() == s1.get_finished(), "tls-unique material: peer Finished matches"
    print("  determinism / length-prefix / label+context separation: OK")
    print("  tls-server-end-point (cert SPKI hash):", lab.tls_server_end_point(c1))


def resume_suite(version: int, tag: str) -> None:
    title(f"2. SESSION RESUMPTION  ({tag})")
    # Same contexts for both handshakes: TLS 1.3 tickets are encrypted under a
    # per-SSL_CTX key, so a fresh server context cannot honour them.
    sctx = lab.server_ctx(version)
    cctx = lab.client_ctx(version)
    c1, s1 = lab.new_pair(cctx, sctx)
    lab.pump(c1, s1)
    lab.settle_ticket(c1, s1)  # required for TLS 1.3; harmless on 1.2
    session = c1.get_session()
    before = lab.Snapshot.take("original", c1, s1)
    print("-- original"); show(before)

    c2, s2 = lab.new_pair(cctx, sctx)
    c2.set_session(session)
    lab.pump(c2, s2)
    after = lab.Snapshot.take("resumed", c2, s2)
    print("-- resumed"); show(after)

    assert lab.resumed_flag(c2) == 1, "second handshake must actually resume"
    print("  SSL_session_reused(client) =", lab.resumed_flag(c2))
    mk_before, mk_after = lab.safe_master_key(c1), lab.safe_master_key(c2)
    if version == lab.TLS12:
        assert mk_before is not None and mk_before == mk_after, "TLS1.2 resumption reuses master secret"
        print("  master key reused across resumption? YES (TLS 1.2 session resumption)")
    else:
        # RFC 8446 derives fresh traffic secrets per connection; OpenSSL 3.x
        # additionally erases the secret post-handshake (master_key() raises),
        # while 4.0 exposes the resumption master secret again. Either way the
        # EKM below rotates, which is the property that matters for binding.
        print("  TLS 1.3 master key readable here?:", mk_before is not None,
              "(OpenSSL 3.x erases it, 4.0 exposes the resumption master secret)")
    assert before.ekm_no_ctx != after.ekm_no_ctx, "EKM must not carry over"
    assert before.local_finished != after.local_finished
    assert before.client_random != after.client_random
    assert before.server_cert_fp == after.server_cert_fp
    assert lab.tls_server_end_point(c1) == lab.tls_server_end_point(c2)
    assert lab.tls_exporter_rfc9266(c1) != lab.tls_exporter_rfc9266(c2)
    print("  EKM / Finished / random rotate even though the session is reused")
    print("  certificate identity (tls-server-end-point) stays the same")


def pha_suite() -> None:
    title("3a. IDENTITY CHANGE - TLS 1.3 POST-HANDSHAKE AUTHENTICATION (PHA)")
    sctx = lab.server_ctx(lab.TLS13)
    # Initial handshake requests NO client certificate (context-level setting).
    _lib.SSL_CTX_set_verify(sctx._context, SSL.VERIFY_NONE, _ffi.NULL)
    cctx = lab.client_ctx(lab.TLS13, client_cert="client-a", post_handshake_auth=True)
    client, server = lab.fresh_handshake(cctx, sctx)
    base = lab.Snapshot.take("before-PHA", client, server)
    print("-- initial handshake (no client cert)"); show(base)
    assert server.get_peer_certificate() is None

    def request_pha():
        _lib.SSL_set_verify(
            server._ssl,
            _lib.SSL_VERIFY_PEER | _lib.SSL_VERIFY_POST_HANDSHAKE,
            _ffi.NULL,
        )
        rc = _lib.SSL_verify_client_post_handshake(server._ssl)
        assert rc == 1, f"SSL_verify_client_post_handshake failed: {rc}"
        # The post-handshake CertificateRequest is flushed on the next record
        # write; an app-data nudge makes the timing deterministic under BIO.
        server.write(b"pha-nudge")
        lab.pump(client, server)

    request_pha()
    after1 = lab.Snapshot.take("after-PHA-a", client, server)
    print("-- after PHA #1 (client-a)"); show(after1)
    assert server.get_peer_certificate() is not None

    # Switch the client identity on the SAME connection and PHA again.
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import serialization as _ser
    new_cert = _x509.load_pem_x509_certificate((lab.HERE / "client-b.pem").read_bytes())
    new_key = _ser.load_pem_private_key((lab.HERE / "client-b.key").read_bytes(), password=None)
    client.use_certificate(new_cert)
    client.use_privatekey(new_key)
    request_pha()
    after2 = lab.Snapshot.take("after-PHA-b", client, server)
    print("-- after PHA #2 (client-b)"); show(after2)

    # The channel is not re-keyed by PHA, so the exporter is identical before
    # and after BOTH identity changes.
    assert base.ekm_no_ctx == after1.ekm_no_ctx == after2.ekm_no_ctx, "PHA must not re-key / change EKM"
    # The server only ever sends its Finished in the initial handshake; a TLS
    # 1.3 PHA carries no new server Finished, so the peer Finished we hold is
    # stable. The CLIENT's get_finished(), however, is overwritten by the
    # Finished inside each post-handshake Authentication message.
    assert base.peer_finished == after1.peer_finished == after2.peer_finished
    assert base.local_finished != after1.local_finished != after2.local_finished, (
        "client get_finished() tracks the LATEST post-handshake Authentication"
    )
    assert after1.client_cert_fp != after2.client_cert_fp, "client identity changed on the wire"
    print("  EKM unchanged across both PHA rounds -> it does NOT encode the client cert")
    print("  server (peer) Finished stable; client get_finished() rewritten per PHA round")
    print("  client cert seen by server changed:", after1.client_cert_fp, "->", after2.client_cert_fp)
    print("  note: RFC9266 transcript-context EKM is not reachable via pyOpenSSL (no transcript API);")
    print("        only application-supplied context can tag the new identity (see suite 4).")


def reneg_suite() -> None:
    title("3b. IDENTITY CHANGE - TLS 1.2 RENEGOTIATION (OpenSSL legacy path)")
    # Start with a client cert already negotiated: OpenSSL 4.0 will not inject a
    # NEW CertificateRequest into a server-initiated renegotiation when the
    # initial handshake had none, and it rejects client-initiated renegotiation
    # outright ("no renegotiation"). What remains reproducible is the re-key.
    sctx = lab.server_ctx(lab.TLS12, allow_reneg=True)
    cctx = lab.client_ctx(lab.TLS12, client_cert="client-a", allow_reneg=True)
    client, server = lab.new_pair(cctx, sctx)
    lab.pump(client, server)
    base = lab.Snapshot.take("before-reneg", client, server)
    print("-- initial handshake (client-a already presented)"); show(base)
    assert server.get_peer_certificate() is not None

    assert server.renegotiate() is True
    # Flush the HelloRequest deterministically under the memory BIO.
    server.write(b"reneg-nudge")
    lab.pump(client, server)
    assert server.renegotiate_pending() is False
    assert server.total_renegotiations() == 1
    after = lab.Snapshot.take("after-reneg", client, server)
    print("-- after server-initiated renegotiation"); show(after)

    assert base.ekm_no_ctx != after.ekm_no_ctx, "renegotiation runs a full new handshake -> new EKM"
    assert base.local_finished != after.local_finished, "get_finished returns the LATEST Finished"
    assert lab.safe_master_key(client) is not None
    assert base.client_random != after.client_random
    assert after.client_cert_fp == base.client_cert_fp, "cert identity is retained, not re-bound"
    print("  total_renegotiations =", server.total_renegotiations())
    print("  EKM / Finished / client_random all changed -> a full re-handshake occurred")
    print("  client cert identity is merely carried over (no fresh auth on this path)")

    # And the documented boundary: OpenSSL 4.0 refuses client-initiated
    # renegotiation, and TLS 1.3 has no renegotiation at all.
    c2, s2 = lab.new_pair(
        lab.client_ctx(lab.TLS12, allow_reneg=True), lab.server_ctx(lab.TLS12, allow_reneg=True)
    )
    lab.pump(c2, s2)
    try:
        c2.renegotiate()
        lab.pump(c2, s2)
        print("  client-initiated renegotiation: unexpectedly accepted")
    except SSL.Error as exc:
        print("  client-initiated renegotiation rejected ->", exc.args[0][0][2])

    s3 = lab.server_ctx(lab.TLS13)
    c3 = lab.client_ctx(lab.TLS13)
    fc, fs = lab.fresh_handshake(c3, s3)
    try:
        fs.renegotiate()
        lab.pump(fc, fs)
        print("  TLS1.3 renegotiate(): unexpectedly accepted (would still be protocol-illegal)")
    except SSL.Error as exc:
        print("  TLS1.3 renegotiate() rejected ->", exc.args[0][0][2])


def proof_suite() -> None:
    title("4. CHANNEL-POSSESSION PROOF vs USER AUTHORIZATION")
    sctx = lab.server_ctx(lab.TLS13)
    cctx = lab.client_ctx(lab.TLS13)
    client, server = lab.fresh_handshake(cctx, sctx)

    challenge = b"server-nonce-7f3d"
    app_context = b"login:tenant-42:session-99"
    label = b"com.example.login-proof"

    def make_proof(conn: SSL.Connection) -> bytes:
        key = conn.export_keying_material(label, 32, app_context)
        return hmac.new(key, challenge, "sha256").digest()

    tag = make_proof(client)
    expected = make_proof(server)
    print("  proof tag (client):", lab.h(tag, 24))
    print("  expected  (server):", lab.h(expected, 24))
    assert hmac.compare_digest(tag, expected)
    # An attacker with a DIFFERENT connection cannot forge the tag.
    other_client, _ = lab.fresh_handshake(cctx, sctx)
    forged = make_proof(other_client)
    assert not hmac.compare_digest(forged, expected)
    print("  tag from a parallel connection does NOT verify: OK")
    # The raw EKM never has to cross the wire.
    raw = client.export_keying_material(label, 32, app_context)
    assert raw not in (tag, challenge)
    print("  raw EKM stays local; only the HMAC tag is presented to the verifier")

    # Long-term identity layer: stable across all connections.
    print("  long-term identity available to the verifier:")
    print("    tls-server-end-point:", lab.tls_server_end_point(client))
    print("  per-connection secrets (EKM, master key, Finished) are NOT identities")


def main() -> None:
    print("OpenSSL:", SSL.SSLeay_version(SSL.SSLEAY_VERSION).decode() if hasattr(SSL, "SSLeay_version") else "n/a")
    fresh_suite(lab.TLS12, "TLS 1.2")
    fresh_suite(lab.TLS13, "TLS 1.3")
    resume_suite(lab.TLS12, "TLS 1.2")
    resume_suite(lab.TLS13, "TLS 1.3")
    pha_suite()
    reneg_suite()
    proof_suite()
    print("\nALL ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
