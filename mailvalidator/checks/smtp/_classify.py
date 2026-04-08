"""Cipher suite, TLS version, and EC curve classification helpers.

NCSC-NL "IT Security Guidelines for TLS" v2.1 tier definitions:

Tier          Criteria
----------    --------------------------------------------------------------
Good          Forward-secret AEAD cipher + strong key exchange
Sufficient    Forward secret but CBC mode, or DHE with higher CPU overhead
Phase-out     No forward secrecy (RSA key exchange) or weak block cipher
Insufficient  Anything else (exported, NULL, eNULL, anonymous, …)
"""

from __future__ import annotations

from mailvalidator.models import Status

# ---------------------------------------------------------------------------
# Cipher classification
# ---------------------------------------------------------------------------

_GOOD_CIPHERS: frozenset[str] = frozenset(
    {
        # TLS 1.3 – always AEAD + ephemeral ECDHE (RFC 8446)
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        # TLS 1.2 – ECDHE-ECDSA + AEAD
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        # TLS 1.2 – ECDHE-RSA + AEAD
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-GCM-SHA256",
    }
)

_SUFFICIENT_CIPHERS: frozenset[str] = frozenset(
    {
        # ECDHE without AEAD (CBC + HMAC)
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA",
        # DHE-RSA (forward-secret but higher CPU overhead)
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-CHACHA20-POLY1305",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-SHA256",
        "DHE-RSA-AES256-SHA",
        "DHE-RSA-AES128-SHA256",
        "DHE-RSA-AES128-SHA",
    }
)

_PHASE_OUT_CIPHERS: frozenset[str] = frozenset(
    {
        # RSA key exchange – no forward secrecy
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES256-SHA",
        "AES128-SHA256",
        "AES128-SHA",
        # 3DES – 64-bit block cipher (Sweet32 vulnerability, CVE-2016-2183)
        "ECDHE-ECDSA-DES-CBC3-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
        "DHE-RSA-DES-CBC3-SHA",
        "DES-CBC3-SHA",
    }
)


def _classify_cipher(name: str) -> Status:
    """Map an OpenSSL cipher suite name to its NCSC-NL security tier.

    :param name: OpenSSL cipher suite name (e.g. ``"ECDHE-RSA-AES256-GCM-SHA384"``).
    :type name: str
    :returns: :attr:`~mailvalidator.models.Status.GOOD`,
        :attr:`~mailvalidator.models.Status.SUFFICIENT`,
        :attr:`~mailvalidator.models.Status.PHASE_OUT`, or
        :attr:`~mailvalidator.models.Status.INSUFFICIENT`.
    :rtype: ~mailvalidator.models.Status
    """
    if name in _GOOD_CIPHERS:
        return Status.GOOD
    if name in _SUFFICIENT_CIPHERS:
        return Status.SUFFICIENT
    if name in _PHASE_OUT_CIPHERS:
        return Status.PHASE_OUT
    return Status.INSUFFICIENT


# ---------------------------------------------------------------------------
# TLS version classification
# ---------------------------------------------------------------------------


def _tls_version_status(version: str) -> Status:
    """Map a TLS version string to its security status.

    :param version: TLS version string as returned by
        :meth:`ssl.SSLSocket.version` (e.g. ``"TLSv1.3"``).
    :type version: str
    :returns: :attr:`~mailvalidator.models.Status.OK` for TLS 1.3,
        :attr:`~mailvalidator.models.Status.SUFFICIENT` for TLS 1.2,
        :attr:`~mailvalidator.models.Status.PHASE_OUT` for TLS 1.0/1.1,
        :attr:`~mailvalidator.models.Status.INSUFFICIENT` otherwise.
    :rtype: ~mailvalidator.models.Status
    """
    if version == "TLSv1.3":
        return Status.OK
    if version == "TLSv1.2":
        return Status.SUFFICIENT
    if version in ("TLSv1.1", "TLSv1"):
        return Status.PHASE_OUT
    return Status.INSUFFICIENT


# ---------------------------------------------------------------------------
# EC curve classification  (NCSC-NL TLS v2.1, table 9)
# ---------------------------------------------------------------------------

_GOOD_EC_CURVES: frozenset[str] = frozenset(
    {
        "secp256r1",
        "prime256v1",  # same curve, two OpenSSL names
        "secp384r1",
        "x448",
        "x25519",
    }
)
_PHASE_OUT_EC_CURVES: frozenset[str] = frozenset({"secp224r1"})


def _classify_ec_curve(curve: str) -> Status:
    """Classify a named EC curve used for key exchange.

    :param curve: Curve name as reported by OpenSSL (e.g. ``"x25519"``).
        Case-insensitive.
    :type curve: str
    :returns: :attr:`~mailvalidator.models.Status.GOOD` for recommended curves,
        :attr:`~mailvalidator.models.Status.PHASE_OUT` for deprecated ones,
        :attr:`~mailvalidator.models.Status.INSUFFICIENT` for other named curves,
        :attr:`~mailvalidator.models.Status.INFO` when the name is empty (not
        exposed by this Python/OpenSSL build).
    :rtype: ~mailvalidator.models.Status
    """
    c = curve.lower()
    if c in _GOOD_EC_CURVES:
        return Status.GOOD
    if c in _PHASE_OUT_EC_CURVES:
        return Status.PHASE_OUT
    if c:
        return Status.INSUFFICIENT
    return Status.INFO


# Alias kept for test compatibility
_classify_ec_curve_kex = _classify_ec_curve


# ---------------------------------------------------------------------------
# Shared lookup tables
# ---------------------------------------------------------------------------

# Severity rank for bubbling up the worst status across a set of ciphers.
# INFO is treated as "unknown" and never overrides a real grade.
_STATUS_RANK: dict[Status, int] = {
    Status.INFO: -1,
    Status.GOOD: 0,
    Status.SUFFICIENT: 1,
    Status.PHASE_OUT: 2,
    Status.INSUFFICIENT: 3,
}

# Icon prefix used when listing individual ciphers in check detail lines.
_CIPHER_ICON: dict[str, str] = {
    "GOOD": "✔",
    "SUFFICIENT": "~",
    "PHASE_OUT": "↓",
    "INSUFFICIENT": "✘",
}

# Hash function tier sets (used by _check_hash_function in _tls_checks)
_SHA_GOOD = {"sha256", "sha384", "sha512"}
_SHA_PHASE_OUT = {"sha1", "sha", "md5"}
