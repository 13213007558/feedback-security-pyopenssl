"""Generate a small test PKI for the EKM / Finished binding study.

Layout (all written next to this file, PEM + PKCS8/PKCS1 as needed):
  ca.pem/ca.key            - root CA, used to sign everything
  server.pem/server.key    - server identity (TLS 1.2 and 1.3)
  client-a.pem/client-a.key - client identity used at initial handshake
  client-b.pem/client-b.key - second client identity used for PHA/renegotiation
"""
from __future__ import annotations

import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
DAYS = datetime.timedelta(days=30)


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _save_key(path: pathlib.Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _save_cert(path: pathlib.Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _ca():
    key = _key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - DAYS)
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + DAYS)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_agreement=False, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(cn: str, ca_key, ca_cert):
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - DAYS)
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + DAYS)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def main() -> None:
    ca_key, ca_cert = _ca()
    _save_key(HERE / "ca.key", ca_key)
    _save_cert(HERE / "ca.pem", ca_cert)

    for cn in ("server", "client-a", "client-b"):
        key, cert = _leaf(f"{cn}.test", ca_key, ca_cert)
        _save_key(HERE / f"{cn}.key", key)
        _save_cert(HERE / f"{cn}.pem", cert)

    print("wrote ca, server, client-a, client-b PEM/key to", HERE)


if __name__ == "__main__":
    main()
