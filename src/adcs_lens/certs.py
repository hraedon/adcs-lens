"""Optional cert/CRL (DER) parsing — the ``[certs]`` extra.

This is the *only* module permitted to import a third-party dependency
(``cryptography``). It is imported lazily by :mod:`adcs_lens.ingest` inside a
``try/except ImportError`` so the deterministic core stays stdlib-only and
air-gappable; when the extra is absent, lifecycle fields are ``None`` and the
lifecycle detector degrades to a note.

Nothing here makes a network call — it parses bytes already on disk.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from adcs_lens.model import CertKind, CertLifecycle, Crl, CrlTier


def _key_bits(cert: x509.Certificate) -> int | None:
    pub = cert.public_key()
    if isinstance(pub, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        return pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.curve.key_size
    return None


def _sig_alg(cert: x509.Certificate) -> str:
    algo = cert.signature_hash_algorithm
    name = algo.name if isinstance(algo, hashes.HashAlgorithm) else "unknown"
    return name.lower()


def _key_alg(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ecdsa"
    if isinstance(pub, dsa.DSAPublicKey):
        return "dsa"
    return "unknown"


def parse_cert(der: bytes, *, kind: CertKind) -> CertLifecycle:
    """Parse a DER certificate into :class:`CertLifecycle`."""
    cert = x509.load_der_x509_certificate(der)
    return CertLifecycle(
        subject=cert.subject.rfc4514_string(),
        kind=kind,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sig_alg=_sig_alg(cert),
        key_bits=_key_bits(cert),
        key_alg=_key_alg(cert),
    )


def parse_crl(der: bytes, *, tier: CrlTier, source: str) -> Crl:
    """Parse a DER CRL into :class:`Crl`."""
    crl = x509.load_der_x509_crl(der)
    return Crl(
        issuer=crl.issuer.rfc4514_string(),
        this_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
        tier=tier,
        source=source,
    )
