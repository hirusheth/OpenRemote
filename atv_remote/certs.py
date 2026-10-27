"""Self-signed client certificate generation for the remote channel.

Evidence: the Google Home app presents a client certificate during the TLS
handshake (REA ev_f2bc304a: SSLSocket built from KeyManagers loaded by
defpackage.asqa, a KeyStore-backed certificate provider). A standalone client
does the same with a locally generated self-signed certificate; the TV learns
to trust it during the PIN pairing handshake (see pairing.py). The
certificate's RSA public key material is also the input to the pairing
secret computation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

#: Default storage for the client certificate/key pair.
DEFAULT_CERT_PATH = "~/.config/openremote/client.pem"
DEFAULT_KEY_PATH = "~/.config/openremote/key.pem"


def generate_client_cert(common_name: str = "OpenRemote") -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) for a fresh self-signed client certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def ensure_client_cert(cert_path: Path, key_path: Path) -> tuple[Path, Path]:
    """Load the client certificate, generating a new one on first run."""
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_pem, key_pem = generate_client_cert()
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_path, key_path


def public_numbers(cert_pem: bytes) -> tuple[int, int]:
    """Extract (modulus, exponent) — used by the pairing secret computation."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    numbers = cert.public_key().public_numbers()  # type: ignore[union-attr]
    return numbers.n, numbers.e
