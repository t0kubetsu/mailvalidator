"""Shared fixtures and helpers used across all mailvalidator test modules.

Import this module's helpers directly in test files::

    from tests.conftest import make_tls, make_cert_der

Or rely on pytest auto-discovery: fixtures defined here are available to
every test in the ``tests/`` tree without any explicit import.
"""

from __future__ import annotations

import datetime as _dt


from mailvalidator.models import (
    MXRecord,
    MXResult,
    TLSDetails,
)


# ---------------------------------------------------------------------------
# TLSDetails factory
# ---------------------------------------------------------------------------


def make_tls(**kwargs) -> TLSDetails:
    """Return a :class:`~mailvalidator.models.TLSDetails` pre-filled with sensible
    defaults, overridden by any *kwargs*.

    :returns: Populated TLSDetails instance.
    :rtype: ~mailvalidator.models.TLSDetails
    """
    defaults = dict(
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        dh_group="x25519",
        dh_bits=256,
        compression="",
        secure_renegotiation=True,
        cert_subject="CN=mail.example.com",
    )
    defaults.update(kwargs)
    return TLSDetails(**defaults)


# ---------------------------------------------------------------------------
# Self-signed DER certificate factories
# ---------------------------------------------------------------------------


def make_rsa_cert_der(
    key_size: int = 2048,
    days: int = 90,
    cn: str = "test.example.com",
    add_san: bool = False,
) -> bytes:
    """Generate and return a self-signed RSA certificate in DER format.

    :param key_size: RSA key size in bits.  Defaults to ``2048``.
    :type key_size: int
    :param days: Certificate validity in days from now.  Defaults to ``90``.
    :type days: int
    :param cn: Common Name for the certificate subject.
    :type cn: str
    :param add_san: When ``True``, add a SAN extension with the CN value.
    :type add_san: bool
    :returns: DER-encoded certificate bytes.
    :rtype: bytes
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=days))
    )
    if add_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def make_ec_cert_der(cn: str = "ec.example.com", days: int = 90) -> bytes:
    """Generate and return a self-signed EC (P-256) certificate in DER format.

    :param cn: Common Name for the certificate subject.
    :type cn: str
    :param days: Certificate validity in days from now.
    :type days: int
    :returns: DER-encoded certificate bytes.
    :rtype: bytes
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Result factories
# ---------------------------------------------------------------------------


def make_mx_result(records: list[MXRecord] | None = None) -> MXResult:
    """Return an :class:`~mailvalidator.models.MXResult` with empty checks.

    :param records: Optional list of MX records.  Defaults to ``[]``.
    :rtype: ~mailvalidator.models.MXResult
    """
    r = MXResult(domain="example.com")
    r.checks = []
    r.records = records or []
    return r


def make_simple_result(cls, domain: str = "example.com"):
    """Return a bare result object of *cls* with empty checks.

    :param cls: Result dataclass to instantiate.
    :param domain: Domain name string.  Defaults to ``"example.com"``.
    :rtype: object
    """
    r = cls(domain=domain)
    r.checks = []
    return r


# ---------------------------------------------------------------------------
# Rich console capture helper
# ---------------------------------------------------------------------------


def console_capture():
    """Return ``(console, buffer)`` — a Rich Console that writes to a StringIO.

    :returns: Tuple of ``(Console, StringIO)`` for capturing rendered output.
    :rtype: tuple
    """
    from io import StringIO
    from rich.console import Console

    buf = StringIO()
    con = Console(file=buf, highlight=False, markup=False, no_color=True, width=120)
    return con, buf
