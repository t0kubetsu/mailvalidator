"""SMTP diagnostics: connectivity, PTR, open relay, STARTTLS, and deep TLS inspection.

Checks performed
----------------

Plain SMTP:

- Connect latency and banner
- Reverse DNS (PTR) for the server IP
- STARTTLS advertisement
- Open relay

TLS (when STARTTLS is available):

- Accepted TLS versions (active per-version probe)
- Accepted cipher suites per version, in server-preference order
- Server cipher-preference enforcement and prescribed ordering
- Key exchange mechanism and group/curve
- Key-exchange hash function
- TLS compression (CRIME attack surface)
- Secure renegotiation (RFC 5746)
- Certificate trust chain, public key, signature algorithm, domain match, and expiry

DNS:

- CAA records (walks up the DNS hierarchy per RFC 8659)
- DANE/TLSA existence, fingerprint verification, and rollover scheme assessment

Design notes
------------
Each TLS probe opens a fresh SMTP connection so that version and cipher
constraints are applied cleanly.  The ``_probe_tls`` function runs once to
collect session metadata; all subsequent check functions read from the
:class:`~mailcheck.models.TLSDetails` object it returns rather than
reconnecting.  Only :func:`_check_dane` may open an additional connection
when the initial probe did not store the DER certificate (rare fallback).
"""

from __future__ import annotations

import hashlib
import ipaddress
import smtplib
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from mailcheck.dns_utils import resolve, reverse_lookup
from mailcheck.models import CheckResult, SMTPDiagResult, Status, TLSDetails

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_TIMEOUT = 10  # seconds per blocking network call

# ---------------------------------------------------------------------------
# Cipher classification  (NCSC-NL "IT Security Guidelines for TLS" v2.1)
# ---------------------------------------------------------------------------
# Tier          Criteria
# ----------    --------------------------------------------------------------
# Good          Forward-secret AEAD cipher + strong key exchange
# Sufficient    Forward secret but CBC mode, or DHE with higher CPU overhead
# Phase-out     No forward secrecy (RSA key exchange) or weak block cipher
# Insufficient  Anything else (exported, NULL, eNULL, anonymous, …)

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
    :returns: :attr:`~mailcheck.models.Status.GOOD`,
        :attr:`~mailcheck.models.Status.SUFFICIENT`,
        :attr:`~mailcheck.models.Status.PHASE_OUT`, or
        :attr:`~mailcheck.models.Status.INSUFFICIENT`.
    :rtype: ~mailcheck.models.Status
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
    :returns: :attr:`~mailcheck.models.Status.OK` for TLS 1.3,
        :attr:`~mailcheck.models.Status.SUFFICIENT` for TLS 1.2,
        :attr:`~mailcheck.models.Status.PHASE_OUT` for TLS 1.0/1.1,
        :attr:`~mailcheck.models.Status.INSUFFICIENT` otherwise.
    :rtype: ~mailcheck.models.Status
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
    :returns: :attr:`~mailcheck.models.Status.GOOD` for recommended curves,
        :attr:`~mailcheck.models.Status.PHASE_OUT` for deprecated ones,
        :attr:`~mailcheck.models.Status.INSUFFICIENT` for other named curves,
        :attr:`~mailcheck.models.Status.INFO` when the name is empty (not
        exposed by this Python/OpenSSL build).
    :rtype: ~mailcheck.models.Status
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


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------


def _cert_info(der: bytes) -> dict:
    """Parse a DER-encoded X.509 certificate and return a flat metadata dict.

    Requires the *cryptography* package (already a project dependency).

    :param der: DER-encoded certificate bytes.
    :type der: bytes
    :returns: Dict with keys ``subject``, ``issuer``, ``not_after``,
        ``sig_alg``, ``san``, ``pubkey_type``, ``pubkey_bits``,
        ``pubkey_curve``.  Returns ``{}`` if parsing fails so callers can
        use :meth:`dict.get` safely.
    :rtype: dict
    """
    try:
        import cryptography.hazmat.primitives.asymmetric.ec as _ec
        import cryptography.hazmat.primitives.asymmetric.rsa as _rsa
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        info: dict = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "sig_alg": (
                cert.signature_hash_algorithm.name
                if cert.signature_hash_algorithm
                else "unknown"
            ),
        }

        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            info["san"] = [n.value for n in san_ext.value]
        except x509.ExtensionNotFound:
            info["san"] = []

        pub = cert.public_key()
        if isinstance(pub, _rsa.RSAPublicKey):
            info.update(pubkey_type="RSA", pubkey_bits=pub.key_size, pubkey_curve="")
        elif isinstance(pub, _ec.EllipticCurvePublicKey):
            info.update(
                pubkey_type="EC", pubkey_bits=pub.key_size, pubkey_curve=pub.curve.name
            )
        else:
            info.update(pubkey_type=type(pub).__name__, pubkey_bits=0, pubkey_curve="")

        return info
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Low-level SMTP / TLS primitives
# ---------------------------------------------------------------------------


def _is_ip(host: str) -> bool:
    """Return ``True`` if *host* is a bare IPv4 or IPv6 address (not a hostname).

    :param host: String to test.
    :type host: str
    :rtype: bool
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _connect_plain(
    host: str, port: int
) -> tuple[smtplib.SMTP, float, str]:  # pragma: no cover
    """Open a plain TCP connection to an SMTP server.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: TCP port to connect to.
    :type port: int
    :returns: Tuple of ``(smtp_client, connect_time_ms, banner_string)``.
    :rtype: tuple[smtplib.SMTP, float, str]
    :raises OSError: On TCP connection failure.
    :raises smtplib.SMTPException: On SMTP-level failure.
    """
    t0 = time.monotonic()
    smtp = smtplib.SMTP(timeout=_TIMEOUT)
    _code, msg = smtp.connect(host, port)
    elapsed_ms = (time.monotonic() - t0) * 1000
    banner = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
    return smtp, elapsed_ms, banner


def _no_verify_ctx(
    tls_min: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    tls_max: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
) -> ssl.SSLContext:
    """Return a ``TLS_CLIENT`` :class:`ssl.SSLContext` that accepts any certificate.

    Used for diagnostic probes where certificates are inspected manually
    rather than relying on the system trust store.

    :param tls_min: Minimum TLS version to negotiate.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version to negotiate.
    :type tls_max: ssl.TLSVersion
    :returns: A no-verify :class:`ssl.SSLContext`.
    :rtype: ssl.SSLContext
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = tls_min
    ctx.maximum_version = tls_max
    return ctx


def _set_sni(smtp: smtplib.SMTP, sni_hostname: str | None, fallback: str) -> None:
    """Set ``smtp._host`` so that smtplib passes the correct SNI ``server_hostname``.

    ``smtplib`` reads ``smtp._host`` when calling ``ssl.wrap_socket()``.
    When ``SMTP()`` is constructed without a host argument (our pattern:
    ``SMTP()`` then ``.connect()``), ``_host`` may be empty, which raises
    ``"server_hostname cannot be empty"`` on Python ≥ 3.13.

    :param smtp: SMTP client instance whose ``_host`` attribute will be set.
    :type smtp: smtplib.SMTP
    :param sni_hostname: Hostname to use for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param fallback: Value to use when *sni_hostname* is ``None``.
    :type fallback: str
    """
    smtp._host = sni_hostname if sni_hostname else fallback  # type: ignore[attr-defined]


def _starttls_and_get_cipher(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    ctx: ssl.SSLContext,
) -> str | None:  # pragma: no cover
    """Perform a STARTTLS handshake with *ctx* and return the negotiated cipher name.

    Opens a fresh connection for each call.  Cleans up the socket whether or
    not the handshake succeeds.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param ctx: Pre-configured :class:`ssl.SSLContext` to use for the handshake.
    :type ctx: ssl.SSLContext
    :returns: Negotiated cipher name, or ``None`` on any failure
        (connection refused, STARTTLS absent, SSL error).
    :rtype: str or None
    """
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException):
        return None
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return None
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        info = smtp.sock.cipher()  # type: ignore[union-attr]
        smtp.quit()
        return info[0] if info else None
    except Exception:
        try:
            smtp.close()
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# TLS probe – collects deep session metadata via STARTTLS
# ---------------------------------------------------------------------------


def _probe_tls(
    host: str,
    port: int,
    helo_domain: str,
) -> tuple[TLSDetails | None, str, str | None]:  # pragma: no cover
    """Connect via STARTTLS and populate a :class:`~mailcheck.models.TLSDetails` object.

    **SNI**: SNI requires a DNS hostname, not an IP address.  For bare IPs
    ``sni_hostname`` is set to ``None`` and ``check_hostname`` is disabled on
    the context, because Python ssl raises ``ValueError: server_hostname cannot
    be empty`` on Python ≥ 3.13.

    **Certificate trust**: the trust chain is verified with a second,
    fully-verifying STARTTLS handshake (``CERT_REQUIRED``, ``check_hostname=False``
    to isolate chain failure from name mismatch).  A bare ``wrap_socket()`` on
    port 25 would fail with ``WRONG_VERSION_NUMBER`` because the server speaks
    plain SMTP until STARTTLS is negotiated.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :returns: Tuple of ``(details, error_message, sni_hostname)``.
        On failure *details* is ``None`` and *error_message* is non-empty.
    :rtype: tuple[TLSDetails or None, str, str or None]
    """
    sni_hostname: str | None = None if _is_ip(host) else host
    details = TLSDetails()

    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException) as exc:
        return None, str(exc), None

    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return None, "STARTTLS not advertised", None

        ctx = _no_verify_ctx()
        if not sni_hostname:
            ctx.check_hostname = False  # required when SNI is skipped
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        smtp.ehlo(helo_domain)  # re-EHLO to discover post-TLS capabilities
    except (smtplib.SMTPException, ValueError) as exc:
        return None, f"STARTTLS failed: {exc}", None

    raw = smtp.sock
    if not isinstance(raw, ssl.SSLSocket):
        smtp.quit()
        return None, "Socket is not an SSLSocket after STARTTLS", None

    # Session metadata
    details.tls_version = raw.version() or ""
    cipher_info = raw.cipher()  # (name, protocol_version, key_bits)
    if cipher_info:
        details.cipher_name = cipher_info[0]
        details.cipher_bits = cipher_info[2] or 0
    details.compression = raw.compression() or ""

    # Key-exchange group – available via the internal _sslobj.group() on some
    # CPython + OpenSSL builds; absent on others – fail silently.
    try:
        sslobj = getattr(raw, "_sslobj", None)
        group_fn = getattr(sslobj, "group", None) if sslobj else None
        if callable(group_fn):
            details.dh_group = group_fn() or ""
    except Exception:
        pass

    # Certificate
    der = raw.getpeercert(binary_form=True)
    if der:
        details._cert_der = der  # type: ignore[attr-defined]  # stashed for DANE reuse
        info = _cert_info(der)
        details.cert_subject = info.get("subject", "")
        details.cert_issuer = info.get("issuer", "")
        details.cert_san = info.get("san", [])
        details.cert_not_after = info.get("not_after", "")
        details.cert_sig_alg = info.get("sig_alg", "")
        details.cert_pubkey_type = info.get("pubkey_type", "")
        details.cert_pubkey_bits = info.get("pubkey_bits", 0)
        details.cert_pubkey_curve = info.get("pubkey_curve", "")

        # Chain-of-trust: second STARTTLS with CERT_REQUIRED but check_hostname=False
        # so a name mismatch does not mask a genuine chain failure.  Hostname
        # correctness is handled separately by _check_certificate.
        if sni_hostname:
            try:
                chain_ctx = ssl.create_default_context()
                chain_ctx.check_hostname = False  # isolate chain from name matching
                chain_smtp = smtplib.SMTP(timeout=_TIMEOUT)
                chain_smtp.connect(host, port)
                chain_smtp.ehlo(helo_domain)
                chain_smtp._host = sni_hostname  # type: ignore[attr-defined]
                chain_smtp.starttls(context=chain_ctx)
                try:
                    chain_smtp.quit()
                except Exception:
                    pass
                details.cert_trusted = True
            except ssl.SSLCertVerificationError:
                details.cert_trusted = False  # chain broken or untrusted root
            except (OSError, smtplib.SMTPException):
                details.cert_trusted = None  # could not connect; result unknown
        else:
            details.cert_trusted = None  # SNI unavailable; cannot verify chain

    # Secure renegotiation: tls-unique channel binding is non-null iff the
    # RFC 5746 Renegotiation Info extension was exchanged.
    try:
        details.secure_renegotiation = raw.get_channel_binding("tls-unique") is not None
    except Exception:
        details.secure_renegotiation = None

    try:
        smtp.quit()
    except Exception:
        pass

    return details, "", sni_hostname


# ---------------------------------------------------------------------------
# TLS version probing
#
# Strategy: pin minimum_version = maximum_version = target and attempt STARTTLS.
#
# TLS 1.0 / 1.1 require SECLEVEL=0 on the client context.  Modern OpenSSL
# defaults to SECLEVEL=2 which rejects the weak ciphers those versions need;
# without lowering it, handshakes fail on our side and the server is falsely
# reported as "not supported".  This is the same approach used by testssl.sh.
#
# TLS 1.0/1.1 entries are added only when the runtime OpenSSL exposes them
# (they are compiled out on hardened builds such as Fedora / RHEL).
# ---------------------------------------------------------------------------

_TLS_VERSION_PROBES: list[tuple[str, ssl.TLSVersion, ssl.TLSVersion]] = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
]
for _label, _attr in (("TLSv1.1", "TLSv1_1"), ("TLSv1", "TLSv1")):
    if hasattr(ssl.TLSVersion, _attr):
        _v = getattr(ssl.TLSVersion, _attr)
        _TLS_VERSION_PROBES.append((_label, _v, _v))

# Versions whose weak ciphers require SECLEVEL=0 to be accepted locally.
_LEGACY_TLS_VERSIONS: frozenset[ssl.TLSVersion] = frozenset(
    getattr(ssl.TLSVersion, attr)
    for attr in ("TLSv1", "TLSv1_1")
    if hasattr(ssl.TLSVersion, attr)
)


def _probe_single_tls_version(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
) -> bool:  # pragma: no cover
    """Return ``True`` if the server completes STARTTLS at exactly this TLS version.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param tls_min: Minimum TLS version (pinned equal to *tls_max*).
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version (pinned equal to *tls_min*).
    :type tls_max: ssl.TLSVersion
    :rtype: bool
    """
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException):
        return False
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return False

        ctx = _no_verify_ctx(tls_min, tls_max)
        if tls_min in _LEGACY_TLS_VERSIONS:
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass  # older OpenSSL without SECLEVEL directive support

        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        smtp.quit()
        return True
    except (smtplib.SMTPException, ssl.SSLError, OSError, ValueError):
        try:
            smtp.close()
        except Exception:
            pass
        return False


def _check_tls_version(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    details: TLSDetails,
    checks: list[CheckResult],
) -> None:
    """Probe each TLS version individually and append a graded summary result.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param details: TLS details object; ``tls_version`` is used in the
        result value field.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which the new
        :class:`~mailcheck.models.CheckResult` is appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    accepted: list[str] = []
    rejected: list[str] = []

    for label, tls_min, tls_max in _TLS_VERSION_PROBES:
        if _probe_single_tls_version(
            host, port, helo_domain, sni_hostname, tls_min, tls_max
        ):
            accepted.append(label)
        else:
            rejected.append(label)

    phase_out_accepted = [
        v for v in accepted if _tls_version_status(v) == Status.PHASE_OUT
    ]
    insufficient_accepted = [
        v for v in accepted if _tls_version_status(v) == Status.INSUFFICIENT
    ]

    if insufficient_accepted:
        overall = Status.INSUFFICIENT
    elif phase_out_accepted:
        overall = Status.PHASE_OUT
    elif any(_tls_version_status(v) == Status.OK for v in accepted):
        overall = Status.GOOD
    elif any(_tls_version_status(v) == Status.SUFFICIENT for v in accepted):
        overall = Status.SUFFICIENT
    else:
        overall = Status.INFO  # all probes failed or were blocked

    _MARKER = {
        "OK": "✔",
        "SUFFICIENT": "✔",
        "PHASE_OUT": "↓ phase-out",
        "INSUFFICIENT": "✘ insecure",
    }
    detail_lines = [
        f"  {_MARKER.get(_tls_version_status(v).value, '✔')}  {v} – accepted"
        for v in accepted
    ] + [f"  –  {v} – not accepted" for v in rejected]
    if phase_out_accepted:
        detail_lines.append(
            f"Disable: {', '.join(phase_out_accepted)} – deprecated protocol(s) still accepted."
        )
    if insufficient_accepted:
        detail_lines.append(
            f"CRITICAL – disable immediately: {', '.join(insufficient_accepted)} – insecure protocol(s) accepted."
        )

    checks.append(
        CheckResult(
            name="TLS Versions",
            status=overall,
            value=f"Best: {details.tls_version}"
            if details.tls_version
            else "negotiated version unknown",
            details=detail_lines,
        )
    )


# ---------------------------------------------------------------------------
# Cipher enumeration
#
# OpenSSL uses two separate APIs for cipher selection:
#   TLS 1.3 suites   →  SSL_CTX_set_ciphersuites  (Python: set_ciphersuites())
#   TLS ≤1.2 ciphers →  SSL_CTX_set_cipher_list   (Python: set_ciphers())
#
# Mixing them causes errors:
#   set_ciphers("TLS_AES_256_GCM_SHA384")  →  SSLError: No cipher can be selected
#   set_ciphersuites(…) may raise AttributeError on older OpenSSL builds
#
# TLS 1.3 and TLS ≤1.2 are therefore handled via completely separate code paths.
# ---------------------------------------------------------------------------

# TLS 1.3 standard ciphersuites (RFC 8446 §B.4), in recommended priority order.
_TLS13_CIPHERSUITES: list[str] = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
]

# TLS ≤1.2 candidate list, ordered Good → Sufficient → Phase-out so that the
# server-order reconstruction phase starts from a sensible initial ordering.
_TLS12_AND_BELOW_CIPHERS: list[str] = [
    # Good – ECDHE-ECDSA + AEAD
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    # Good – ECDHE-RSA + AEAD
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256",
    # Sufficient – ECDHE + CBC
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA",
    # Sufficient – DHE-RSA
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES128-SHA",
    # Phase-out – RSA key exchange (no forward secrecy)
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES256-SHA",
    "AES128-SHA256",
    "AES128-SHA",
    # Phase-out – 3DES (Sweet32)
    "ECDHE-ECDSA-DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "DHE-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
]

# Flat union used by helpers that reference both lists.
_ALL_KNOWN_CIPHERS: list[str] = _TLS13_CIPHERSUITES + _TLS12_AND_BELOW_CIPHERS


def _make_cipher_probe_ctx(
    cipher: str,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
    seclevel0: bool = False,
) -> ssl.SSLContext:
    """Build a no-verify :class:`ssl.SSLContext` restricted to one cipher and version range.

    **TLS 1.3**: a context pinned to ``TLSv1_3`` (min=max) already contains
    only the three standard suites.  Calling :meth:`ssl.SSLContext.set_ciphers`
    with a TLS 1.3 name raises :exc:`ssl.SSLError` on most builds, so the
    cipher list is left alone; the version pin is the restriction.

    **TLS ≤1.2**: :meth:`ssl.SSLContext.set_ciphers` is called for the target
    cipher, and :meth:`ssl.SSLContext.set_ciphersuites` (where available)
    suppresses TLS 1.3 suites.

    :param cipher: OpenSSL cipher name to restrict the context to.
    :type cipher: str
    :param tls_min: Minimum TLS version.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version.
    :type tls_max: ssl.TLSVersion
    :param seclevel0: When ``True``, append ``":@SECLEVEL=0"`` to the cipher
        string to allow weak ciphers required by TLS 1.0/1.1.
    :type seclevel0: bool
    :returns: Configured no-verify :class:`ssl.SSLContext`.
    :rtype: ssl.SSLContext
    :raises ssl.SSLError: If *cipher* is not recognised by OpenSSL.
    """
    ctx = _no_verify_ctx(tls_min, tls_max)

    if tls_min != ssl.TLSVersion.TLSv1_3:
        cipher_str = f"{cipher}:@SECLEVEL=0" if seclevel0 else cipher
        ctx.set_ciphers(cipher_str)  # raises ssl.SSLError if the name is unknown
        try:
            ctx.set_ciphersuites("")  # type: ignore[attr-defined]
        except (ssl.SSLError, AttributeError):
            pass  # older OpenSSL; version pin is sufficient

    return ctx


def _try_cipher(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    cipher: str,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
    seclevel0: bool = False,
) -> bool:  # pragma: no cover
    """Return ``True`` if the server accepts *cipher* for the given TLS version.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param cipher: OpenSSL cipher name to probe.
    :type cipher: str
    :param tls_min: Minimum TLS version.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version.
    :type tls_max: ssl.TLSVersion
    :param seclevel0: Lower OpenSSL SECLEVEL to 0 for legacy cipher support.
    :type seclevel0: bool
    :rtype: bool
    """
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException):
        return False
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return False
        ctx = _make_cipher_probe_ctx(cipher, tls_min, tls_max, seclevel0=seclevel0)
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        smtp.quit()
        return True
    except (smtplib.SMTPException, ssl.SSLError, OSError, ValueError):
        try:
            smtp.close()
        except Exception:
            pass
        return False


def _enumerate_tls13_ciphers(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
) -> list[str]:  # pragma: no cover
    """Return the accepted TLS 1.3 ciphersuites in server-preference order.

    When :meth:`ssl.SSLContext.set_ciphersuites` is available, each suite is
    probed in isolation.  On older OpenSSL builds a single connection is made
    and all three standard suites are reported as accepted (they cannot be
    isolated without the API).

    Results are returned in RFC 8446 standard order (strongest first), which
    is the order servers are required to enforce.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :returns: Accepted TLS 1.3 suite names in server-preference order.
    :rtype: list[str]
    """
    has_set_ciphersuites = hasattr(
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), "set_ciphersuites"
    )
    accepted: set[str] = set()

    if has_set_ciphersuites:
        for suite in _TLS13_CIPHERSUITES:
            ctx = _no_verify_ctx(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
            ctx.set_ciphersuites(suite)  # type: ignore[attr-defined]
            negotiated = _starttls_and_get_cipher(
                host, port, helo_domain, sni_hostname, ctx
            )
            if negotiated == suite:
                accepted.add(suite)
    else:
        # Fallback: one connection reveals the server's top-preferred suite.
        ctx = _no_verify_ctx(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
        negotiated = _starttls_and_get_cipher(
            host, port, helo_domain, sni_hostname, ctx
        )
        if negotiated in _TLS13_CIPHERSUITES:
            # Cannot isolate individual suites; report all three as accepted.
            accepted.update(_TLS13_CIPHERSUITES)

    return [s for s in _TLS13_CIPHERSUITES if s in accepted]


def _enumerate_ciphers_for_version(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
    *,
    max_workers: int = 10,
) -> list[str]:  # pragma: no cover
    """Return accepted ciphers for one TLS version in server-preference order.

    TLS 1.3 is delegated to :func:`_enumerate_tls13_ciphers` (separate API
    path required by OpenSSL).

    TLS ≤1.2 uses two phases:

    1. **Parallel acceptance probe** – all candidate ciphers are tried
       concurrently with :class:`~concurrent.futures.ThreadPoolExecutor` to
       build the accepted set quickly.
    2. **Server-order reconstruction** – offer the full accepted set; whichever
       cipher the server negotiates first is its most-preferred.  Remove it and
       repeat until the list is exhausted or a round fails.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param tls_min: Minimum TLS version to pin the probe to.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version to pin the probe to.
    :type tls_max: ssl.TLSVersion
    :param max_workers: Maximum parallel threads for phase 1.  Defaults to ``10``.
    :type max_workers: int
    :returns: Accepted cipher names in server-preference order.
    :rtype: list[str]
    """
    if tls_min == ssl.TLSVersion.TLSv1_3:
        return _enumerate_tls13_ciphers(host, port, helo_domain, sni_hostname)

    is_legacy = tls_min in _LEGACY_TLS_VERSIONS

    # Phase 1: parallel acceptance probe
    accepted: set[str] = set()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _try_cipher,
                host,
                port,
                helo_domain,
                sni_hostname,
                c,
                tls_min,
                tls_max,
                is_legacy,
            ): c
            for c in _TLS12_AND_BELOW_CIPHERS
        }
        for fut in as_completed(futures):
            try:
                if fut.result():
                    accepted.add(futures[fut])
            except Exception:
                pass

    if not accepted:
        return []

    # Phase 2: reconstruct server-preference order
    remaining = list(accepted)
    ordered: list[str] = []

    while remaining:
        if len(remaining) == 1:
            ordered.append(remaining.pop())
            break

        cipher_list = ":".join(remaining)
        if is_legacy:
            cipher_list += ":@SECLEVEL=0"

        ctx = _no_verify_ctx(tls_min, tls_max)
        try:
            ctx.set_ciphers(cipher_list)
        except ssl.SSLError:
            ordered.extend(remaining)
            break

        chosen = _starttls_and_get_cipher(host, port, helo_domain, sni_hostname, ctx)
        if chosen and chosen in remaining:
            ordered.append(chosen)
            remaining.remove(chosen)
        else:
            # Server did not pick any of our candidates (e.g. it closed mid-probe).
            ordered.extend(remaining)
            break

    return ordered


def _detect_server_cipher_order(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    accepted: list[str],
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
) -> bool | None:  # pragma: no cover
    """Return ``True`` if the server enforces its own cipher-preference order.

    Technique: offer the top two accepted ciphers in both orderings (A:B and
    B:A) and check whether the server always selects the same cipher.  If so
    the server has a fixed preference; if not, it mirrors the client order.

    TLS 1.3: RFC 8446 §4.2.9 mandates server-enforced ordering, so ``True``
    is returned unconditionally without probing (``set_ciphers()`` rejects
    TLS 1.3 names anyway).

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param accepted: Ordered list of accepted cipher names from the initial
        enumeration; at least two are required.
    :type accepted: list[str]
    :param tls_min: Minimum TLS version pin.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version pin.
    :type tls_max: ssl.TLSVersion
    :returns: ``True`` if server enforces order, ``False`` if it follows the
        client, ``None`` if the result could not be determined (fewer than
        two accepted ciphers).
    :rtype: bool or None
    """
    if tls_min == ssl.TLSVersion.TLSv1_3:
        return True

    if len(accepted) < 2:
        return None

    a, b = accepted[0], accepted[1]
    is_legacy = tls_min in _LEGACY_TLS_VERSIONS

    def _pick(first: str, second: str) -> str | None:
        """Offer *first*:*second* to the server and return the cipher it selects.

        :param first: Cipher name to offer first (client preference).
        :type first: str
        :param second: Cipher name to offer second.
        :type second: str
        :returns: The cipher name the server negotiated, or ``None`` on failure.
        :rtype: str or None
        """
        cipher_list = f"{first}:{second}"
        if is_legacy:
            cipher_list += ":@SECLEVEL=0"
        ctx = _no_verify_ctx(tls_min, tls_max)
        try:
            ctx.set_ciphers(cipher_list)
        except ssl.SSLError:
            return None
        return _starttls_and_get_cipher(host, port, helo_domain, sni_hostname, ctx)

    pick_ab = _pick(a, b)
    pick_ba = _pick(b, a)

    if pick_ab is None or pick_ba is None:
        return None
    return pick_ab == pick_ba  # same winner regardless of client order → enforced


# ---------------------------------------------------------------------------
# Version map: label → (TLSVersion min, TLSVersion max)
# Built once at import time; shared by _check_cipher and _check_cipher_order.
# ---------------------------------------------------------------------------


def _build_version_map() -> dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]]:
    """Build the label-to-version-range map for all supported TLS versions.

    :returns: Mapping of TLS version label to ``(min, max)`` version tuple.
    :rtype: dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]]
    """
    m: dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]] = {
        "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    }
    for attr, label in (("TLSv1_1", "TLSv1.1"), ("TLSv1", "TLSv1")):
        if hasattr(ssl.TLSVersion, attr):
            v = getattr(ssl.TLSVersion, attr)
            m[label] = (v, v)
    return m


_VERSION_MAP: dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]] = _build_version_map()


# ---------------------------------------------------------------------------
# Check: cipher suites
# ---------------------------------------------------------------------------


def _check_cipher(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    details: TLSDetails,
    checks: list[CheckResult],
) -> None:
    """Enumerate accepted ciphers per TLS version and emit a graded result for each.

    Per-version ordered lists are stored on the dynamic attribute
    ``details.offered_ciphers_by_version`` so that :func:`_check_cipher_order`
    can reuse them without making a second round of network probes.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param details: TLS details object; ``offered_ciphers_by_version`` and
        ``offered_ciphers`` are populated as a side-effect.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which per-version
        :class:`~mailcheck.models.CheckResult` items are appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    details.offered_ciphers_by_version: dict[str, list[str]] = {}  # type: ignore[attr-defined]

    for ver_label, (tls_min, tls_max) in _VERSION_MAP.items():
        ciphers = _enumerate_ciphers_for_version(
            host, port, helo_domain, sni_hostname, tls_min, tls_max
        )
        if not ciphers:
            continue

        details.offered_ciphers_by_version[ver_label] = ciphers  # type: ignore[attr-defined]

        ver_worst = Status.GOOD
        detail_lines: list[str] = []
        for c in ciphers:
            st = _classify_cipher(c)
            icon = _CIPHER_ICON.get(st.value, "?")
            detail_lines.append(f"  {icon} [{st.value}] {c}")
            if _STATUS_RANK.get(st, 0) > _STATUS_RANK.get(ver_worst, 0):
                ver_worst = st

        checks.append(
            CheckResult(
                name=f"Cipher Suites ({ver_label})",
                status=ver_worst,
                value=f"{len(ciphers)} cipher(s)",
                details=detail_lines,
            )
        )

    # Flat deduped list for backward compatibility with other checks
    seen: set[str] = set()
    flat: list[str] = []
    for lst in details.offered_ciphers_by_version.values():  # type: ignore[attr-defined]
        for c in lst:
            if c not in seen:
                seen.add(c)
                flat.append(c)
    details.offered_ciphers = flat


# ---------------------------------------------------------------------------
# Check: cipher order
# ---------------------------------------------------------------------------


def _check_cipher_order(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    details: TLSDetails,
    checks: list[CheckResult],
) -> None:
    """Check server cipher-preference enforcement and prescribed ordering per version.

    Must be called after :func:`_check_cipher` so that
    ``details.offered_ciphers_by_version`` is populated.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param details: TLS details object; reads ``offered_ciphers_by_version``.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which per-version
        :class:`~mailcheck.models.CheckResult` items are appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    by_version: dict[str, list[str]] = getattr(
        details, "offered_ciphers_by_version", {}
    )

    if not by_version:
        checks.append(
            CheckResult(
                name="Cipher Order",
                status=Status.INFO,
                details=["No cipher enumeration data available."],
            )
        )
        return

    order_rank = {
        Status.GOOD: 0,
        Status.SUFFICIENT: 1,
        Status.PHASE_OUT: 2,
        Status.INSUFFICIENT: 3,
    }

    for ver_label, ciphers in by_version.items():
        tls_min, tls_max = _VERSION_MAP.get(
            ver_label, (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        )

        # Server-preference enforcement
        enforced = _detect_server_cipher_order(
            host, port, helo_domain, sni_hostname, ciphers, tls_min, tls_max
        )
        if enforced is True:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Server Preference ({ver_label})",
                    status=Status.OK,
                    value="Enforced",
                )
            )
        elif enforced is False:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Server Preference ({ver_label})",
                    status=Status.WARNING,
                    value="Not enforced",
                    details=[
                        "Server follows the client's cipher preference rather than its own."
                    ],
                )
            )
        else:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Server Preference ({ver_label})",
                    status=Status.INFO,
                    details=["Could not determine (need ≥2 accepted ciphers)."],
                )
            )

        # Prescribed ordering: Good → Sufficient → Phase-out
        categories = [_classify_cipher(c) for c in ciphers]
        ranks = [order_rank.get(s, 3) for s in categories]

        if set(categories) <= {Status.GOOD}:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Prescribed Ordering ({ver_label})",
                    status=Status.NA,
                    value="N/A (all ciphers are Good)",
                )
            )
        elif ranks == sorted(ranks):
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Prescribed Ordering ({ver_label})",
                    status=Status.OK,
                    value="Correct",
                )
            )
        else:
            correct = sorted(
                ciphers, key=lambda c: order_rank.get(_classify_cipher(c), 3)
            )
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Prescribed Ordering ({ver_label})",
                    status=Status.WARNING,
                    value="Incorrect",
                    details=[
                        "Ciphers should be ordered: Good → Sufficient → Phase-out.",
                        "Actual order:  " + ", ".join(ciphers),
                        "Recommended:   " + ", ".join(correct),
                    ],
                )
            )


# ---------------------------------------------------------------------------
# Check: key exchange
# ---------------------------------------------------------------------------


def _check_key_exchange(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Assess the key exchange mechanism used in the negotiated TLS session.

    **TLS 1.3**: ephemeral ECDHE is mandatory (RFC 8446 §4.2.7).  Python ssl
    does not expose the negotiated ``NamedGroup`` on most builds; when the
    group name is unavailable the check reports ``GOOD`` with an informational
    note.

    **TLS ≤1.2**: the mechanism is inferred from the cipher name prefix:

    - ``ECDHE-*`` → EC Diffie-Hellman; the named curve is classified.
    - ``DHE-*``   → finite-field DH; assessed by key size in bits.
    - other       → static RSA key exchange (no forward secrecy; phase-out).

    :param details: TLS details object containing session metadata.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which :class:`~mailcheck.models.CheckResult`
        items are appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    tls_ver = details.tls_version
    cipher = details.cipher_name

    # TLS 1.3 – always ephemeral ECDHE per RFC 8446
    if tls_ver == "TLSv1.3" and cipher.startswith("TLS_"):
        group = details.dh_group or ""
        if group:
            st = _classify_ec_curve(group)
            msg = (
                [f"Curve {group} is deprecated; prefer x25519 or secp256r1."]
                if st == Status.PHASE_OUT
                else [f"Curve {group} is not recommended for key exchange."]
                if st == Status.INSUFFICIENT
                else []
            )
            checks.append(
                CheckResult(
                    name="Key Exchange – EC Curve",
                    status=st,
                    value=f"ECDHE ({group})",
                    details=msg,
                )
            )
        else:
            checks.append(
                CheckResult(
                    name="Key Exchange – EC Curve",
                    status=Status.GOOD,
                    value="ECDHE (TLS 1.3 – group not exposed by this Python/OpenSSL build)",
                    details=[
                        "TLS 1.3 mandates ephemeral ECDHE (RFC 8446 §4.2.7). "
                        "Use testssl.sh to confirm the exact group."
                    ],
                )
            )
        return

    # TLS ≤1.2 – derive mechanism from cipher name prefix
    if "ECDHE" in cipher:
        curve = details.dh_group or ""  # NOTE: cert pubkey curve ≠ kex curve
        st = _classify_ec_curve(curve)
        msg = (
            [f"Curve {curve} is deprecated; migrate to secp256r1 or secp384r1."]
            if st == Status.PHASE_OUT
            else [f"Curve {curve} is not considered secure for key exchange."]
            if st == Status.INSUFFICIENT
            else [
                "EC curve not exposed by this Python/OpenSSL build; verify with testssl.sh."
            ]
            if st == Status.INFO
            else []
        )
        checks.append(
            CheckResult(
                name="Key Exchange – EC Curve",
                status=st,
                value=f"ECDHE ({curve})" if curve else "ECDHE (curve unknown)",
                details=msg,
            )
        )

    elif "DHE" in cipher:
        bits = details.dh_bits or 0
        if bits >= 3072:
            st2, note = Status.SUFFICIENT, ""
        elif bits >= 2048:
            st2, note = (
                Status.PHASE_OUT,
                "ffdhe2048 – phase-out; upgrade to ≥3072-bit group.",
            )
        elif bits > 0:
            st2, note = Status.INSUFFICIENT, f"{bits}-bit DH group is insecure."
        else:
            st2, note = (
                Status.INFO,
                "DH group size not exposed by this Python/OpenSSL build.",
            )
        checks.append(
            CheckResult(
                name="Key Exchange – DH Group",
                status=st2,
                value=f"{bits} bit" if bits else "unknown",
                details=[note] if note else [],
            )
        )

    else:
        # RSA key exchange: no forward secrecy
        checks.append(
            CheckResult(
                name="Key Exchange",
                status=Status.PHASE_OUT,
                value=f"RSA ({cipher})",
                details=[
                    "RSA key exchange provides no forward secrecy. Migrate to ECDHE or DHE ciphers."
                ],
            )
        )


# ---------------------------------------------------------------------------
# Check: key-exchange hash function
# ---------------------------------------------------------------------------

_SHA_GOOD = {"sha256", "sha384", "sha512"}
_SHA_PHASE_OUT = {"sha1", "sha", "md5"}


def _check_hash_function(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Report the hash algorithm used to sign the key-exchange parameters.

    TLS 1.3 always uses HKDF with SHA-256 or SHA-384; no per-cipher
    inspection is needed.  For TLS ≤1.2 the hash is the last hyphen-delimited
    token of the cipher name (e.g. ``ECDHE-RSA-AES256-GCM-SHA384``).

    :param details: TLS details object; reads ``tls_version`` and
        ``cipher_name``.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which a :class:`~mailcheck.models.CheckResult`
        is appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    if details.tls_version == "TLSv1.3":
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)",
                status=Status.GOOD,
                value="SHA-256/384 (TLS 1.3 HKDF)",
            )
        )
        return

    found: str | None = None
    for part in details.cipher_name.lower().split("-"):
        if part in _SHA_GOOD or part in _SHA_PHASE_OUT:
            found = part.upper()
            break

    if found and found.lower() in _SHA_GOOD:
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)", status=Status.GOOD, value=found
            )
        )
    elif found:
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)",
                status=Status.PHASE_OUT,
                value=found,
                details=[
                    f"{found} is weak for key-exchange signatures; upgrade to SHA-256 or better."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)",
                status=Status.INFO,
                value="(unable to determine)",
            )
        )


# ---------------------------------------------------------------------------
# Check: TLS compression (CRIME attack)
# ---------------------------------------------------------------------------


def _check_compression(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Flag TLS-layer compression, which enables the CRIME attack (CVE-2012-4929).

    :param details: TLS details object; reads ``compression``.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which a :class:`~mailcheck.models.CheckResult`
        is appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    comp = details.compression
    if not comp:
        checks.append(
            CheckResult(
                name="TLS Compression",
                status=Status.GOOD,
                value="None",
                details=["No TLS-level compression (CRIME-safe)."],
            )
        )
    elif comp.lower() in ("deflate", "zlib"):
        checks.append(
            CheckResult(
                name="TLS Compression",
                status=Status.INSUFFICIENT,
                value=comp,
                details=[
                    "TLS-layer compression is enabled. Disable immediately to prevent CRIME attacks."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="TLS Compression",
                status=Status.SUFFICIENT,
                value=comp,
                details=[
                    "Application-level compression detected (not CRIME-vulnerable by itself)."
                ],
            )
        )


# ---------------------------------------------------------------------------
# Check: renegotiation (RFC 5746)
# ---------------------------------------------------------------------------


def _check_renegotiation(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Check for RFC 5746 secure renegotiation support.

    TLS 1.3 eliminates renegotiation entirely (replaced by Key Update); both
    sub-checks are reported as N/A.

    For TLS ≤1.2, secure-renegotiation support is inferred from the
    ``tls-unique`` channel binding: a non-null value implies the
    Renegotiation Info extension (RI) was exchanged, satisfying RFC 5746.

    Client-initiated renegotiation cannot be actively probed in pure Python
    (it would require sending a ``ClientHello`` mid-session); it is flagged
    for manual verification instead.

    :param details: TLS details object; reads ``tls_version`` and
        ``secure_renegotiation``.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which :class:`~mailcheck.models.CheckResult`
        items are appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    if details.tls_version == "TLSv1.3":
        checks.append(
            CheckResult(
                name="Secure Renegotiation", status=Status.GOOD, value="N/A (TLS 1.3)"
            )
        )
        checks.append(
            CheckResult(
                name="Client-Initiated Renegotiation",
                status=Status.GOOD,
                value="N/A (TLS 1.3)",
            )
        )
        return

    sr = details.secure_renegotiation
    if sr is True:
        checks.append(
            CheckResult(
                name="Secure Renegotiation", status=Status.GOOD, value="Supported"
            )
        )
    elif sr is False:
        checks.append(
            CheckResult(
                name="Secure Renegotiation",
                status=Status.INSUFFICIENT,
                value="Not supported",
                details=[
                    "RFC 5746 Renegotiation Info extension absent; server may be vulnerable to renegotiation attacks."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Secure Renegotiation",
                status=Status.INFO,
                value="(unable to determine)",
            )
        )

    checks.append(
        CheckResult(
            name="Client-Initiated Renegotiation",
            status=Status.INFO,
            details=[
                "Active probe not performed. Verify server-side configuration manually."
            ],
        )
    )


# ---------------------------------------------------------------------------
# Check: certificate
# ---------------------------------------------------------------------------


def _check_certificate(
    details: TLSDetails,
    checks: list[CheckResult],
    host: str,
) -> None:
    """Report trust chain, public key, signature algorithm, domain match, and expiry.

    :param details: TLS details object containing parsed certificate metadata.
    :type details: ~mailcheck.models.TLSDetails
    :param checks: List to which :class:`~mailcheck.models.CheckResult`
        items are appended.
    :type checks: list[~mailcheck.models.CheckResult]
    :param host: Hostname used in the SMTP connection; checked against the
        certificate SAN/CN.
    :type host: str
    """
    if not details.cert_subject:
        checks.append(
            CheckResult(
                name="Certificate",
                status=Status.INFO,
                details=["No certificate information available."],
            )
        )
        return

    # Trust chain
    # cert_trusted=True  → chain verified against system trust store
    # cert_trusted=False → chain broken or self-signed (SSLCertVerificationError)
    # cert_trusted=None  → could not verify (bare IP or connection failure)
    if details.cert_trusted is True:
        trust_status, trust_value, trust_detail = Status.GOOD, "Trusted", []
    elif details.cert_trusted is False:
        trust_status = Status.WARNING
        trust_value = "Untrusted / self-signed"
        trust_detail = [
            "Certificate chain could not be verified against the system trust store. "
            "The certificate may be self-signed or issued by an unknown CA."
        ]
    else:
        trust_status = Status.INFO
        trust_value = "Unknown"
        trust_detail = [
            "Chain-of-trust could not be checked "
            "(bare IP address or connection failure during verification)."
        ]
    checks.append(
        CheckResult(
            name="Certificate Trust Chain",
            status=trust_status,
            value=trust_value,
            details=trust_detail,
        )
    )

    # Public key strength
    pk_type = details.cert_pubkey_type
    pk_bits = details.cert_pubkey_bits
    pk_curve = details.cert_pubkey_curve

    if pk_type == "RSA":
        if pk_bits >= 3072:
            pk_status, pk_note = Status.GOOD, ""
        elif pk_bits >= 2048:
            pk_status, pk_note = (
                Status.SUFFICIENT,
                "2048-bit RSA is acceptable but ≥3072 bit is recommended.",
            )
        else:
            pk_status, pk_note = (
                Status.INSUFFICIENT,
                f"{pk_bits}-bit RSA key is too short; reissue with ≥2048 bit.",
            )
        checks.append(
            CheckResult(
                name="Certificate Public Key",
                status=pk_status,
                value=f"RSA {pk_bits} bit",
                details=[pk_note] if pk_note else [],
            )
        )
    elif pk_type == "EC":
        curve_status = _classify_ec_curve(pk_curve)
        checks.append(
            CheckResult(
                name="Certificate Public Key",
                status=curve_status,
                value=f"EC {pk_curve} ({pk_bits} bit)",
                details=(
                    [f"Curve {pk_curve} is deprecated; reissue with P-256 or P-384."]
                    if curve_status == Status.PHASE_OUT
                    else [f"Curve {pk_curve} is not recommended."]
                    if curve_status == Status.INSUFFICIENT
                    else []
                ),
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Certificate Public Key", status=Status.INFO, value=pk_type
            )
        )

    # Signature algorithm
    sig_alg = details.cert_sig_alg.lower()
    if any(h in sig_alg for h in ("sha256", "sha384", "sha512")):
        sig_status = Status.GOOD
    elif any(h in sig_alg for h in ("sha1", "md5")):
        sig_status = Status.INSUFFICIENT
    else:
        sig_status = Status.INFO
    checks.append(
        CheckResult(
            name="Certificate Signature",
            status=sig_status,
            value=details.cert_sig_alg,
            details=(
                [
                    "SHA-1/MD5 signatures are cryptographically broken; reissue the certificate with SHA-256+."
                ]
                if sig_status == Status.INSUFFICIENT
                else []
            ),
        )
    )

    # Domain match: SAN takes precedence over CN (RFC 6125)
    hostname = host.lower()
    san = details.cert_san
    if san:
        matched = any(
            hostname == n.lower()
            or (n.startswith("*.") and hostname.endswith(n[1:].lower()))
            for n in san
        )
    else:
        matched = f"cn={hostname}" in details.cert_subject.lower()

    checks.append(
        CheckResult(
            name="Certificate Domain Match",
            status=Status.OK if matched else Status.WARNING,
            value="Match" if matched else "Mismatch",
            details=[]
            if matched
            else [
                f"Hostname '{host}' not found in certificate SAN/CN. "
                "Note: SMTP senders typically ignore name mismatch unless DANE-TA is used."
            ],
        )
    )

    # Expiry
    if details.cert_not_after:
        try:
            expiry = datetime.fromisoformat(details.cert_not_after)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(tz=timezone.utc)).days
            if days_left < 0:
                exp_status, exp_detail = Status.ERROR, ["Certificate has EXPIRED."]
            elif days_left < 30:
                exp_status, exp_detail = (
                    Status.WARNING,
                    [f"Certificate expires in {days_left} day(s) – renew soon."],
                )
            else:
                exp_status, exp_detail = (
                    Status.OK,
                    [f"Valid for {days_left} more days (expires {expiry.date()})."],
                )
            checks.append(
                CheckResult(
                    name="Certificate Expiry",
                    status=exp_status,
                    value=str(expiry.date()),
                    details=exp_detail,
                )
            )
        except ValueError:
            checks.append(
                CheckResult(
                    name="Certificate Expiry",
                    status=Status.INFO,
                    value=details.cert_not_after,
                )
            )


# ---------------------------------------------------------------------------
# Check: CAA records (RFC 8659)
# ---------------------------------------------------------------------------


def _check_caa(host: str, checks: list[CheckResult]) -> None:
    """Look up CAA records, walking up the DNS hierarchy from *host*.

    RFC 8659 requires at least one ``issue`` or ``issuewild`` tag to
    restrict which CAs may issue certificates for the domain.  A plain-HTTP
    ``iodef`` URL is flagged because incident reports sent over HTTP can be
    intercepted or tampered with.

    :param host: MX hostname to start the DNS hierarchy walk from.
    :type host: str
    :param checks: List to which a :class:`~mailcheck.models.CheckResult`
        is appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    labels = host.rstrip(".").split(".")
    caa_records: list[str] = []
    found_at = ""

    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        records = resolve(candidate, "CAA")
        if records:
            caa_records = records
            found_at = candidate
            break

    if not caa_records:
        checks.append(
            CheckResult(
                name="CAA Records",
                status=Status.WARNING,
                details=[
                    f"No CAA records found for {host} or any parent domain. "
                    "Any CA can currently issue certificates for this domain."
                ],
            )
        )
        return

    issues: list[str] = []
    if not any("issue " in r or r.strip().endswith("issue") for r in caa_records):
        issues.append("No 'issue' tag found; add at least one CAA 'issue' record.")
    if any(
        "iodef" in r and "http://" in r and "https://" not in r for r in caa_records
    ):
        issues.append(
            "iodef URL uses plain HTTP; switch to HTTPS to protect incident reports."
        )
    if not all(len(r.split()) >= 3 for r in caa_records):
        issues.append(
            "One or more CAA records appear malformed (expected: flags tag value)."
        )

    checks.append(
        CheckResult(
            name="CAA Records",
            status=Status.OK if not issues else Status.WARNING,
            value=f"{len(caa_records)} record(s) at {found_at}",
            details=caa_records + issues,
        )
    )


# ---------------------------------------------------------------------------
# DANE / TLSA verification (RFC 6698, RFC 7671)
# ---------------------------------------------------------------------------


def _tlsa_fingerprint(der: bytes, selector: int, matching: int) -> str | None:
    """Compute a TLSA record fingerprint from a DER-encoded certificate.

    :param der: DER-encoded certificate bytes.
    :type der: bytes
    :param selector: ``0`` = full certificate DER;
        ``1`` = SubjectPublicKeyInfo (SPKI) DER.
    :type selector: int
    :param matching: ``0`` = exact hex match; ``1`` = SHA-256; ``2`` = SHA-512.
    :type matching: int
    :returns: Lowercase hex fingerprint string, or ``None`` for unsupported
        selector/matching combinations or parse errors.
    :rtype: str or None
    """
    try:
        if selector == 0:
            data = der
        elif selector == 1:
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )

            cert = _x509.load_der_x509_certificate(der)
            data = cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        else:
            return None

        if matching == 0:
            return data.hex()
        elif matching == 1:
            return hashlib.sha256(data).hexdigest()
        elif matching == 2:
            return hashlib.sha512(data).hexdigest()
        return None
    except Exception:
        return None


def _verify_tlsa_record(record_str: str, cert_der: bytes) -> tuple[bool, str]:
    """Compare one TLSA record against the server certificate.

    :param record_str: Raw DNS TLSA value, e.g. ``"3 1 1 abcdef…"``.
    :type record_str: str
    :param cert_der: DER-encoded server certificate bytes.
    :type cert_der: bytes
    :returns: Tuple ``(matches, description)`` where *matches* is ``True``
        when the record fingerprint matches the certificate.
    :rtype: tuple[bool, str]
    """
    parts = record_str.split()
    if len(parts) < 4:
        return False, f"Malformed TLSA record: {record_str!r}"
    try:
        usage, selector, matching = int(parts[0]), int(parts[1]), int(parts[2])
        dns_hex = "".join(parts[3:]).lower()
    except ValueError:
        return False, f"Could not parse TLSA fields: {record_str!r}"

    usage_name = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}.get(
        usage, str(usage)
    )
    selector_name = {0: "Cert", 1: "SPKI"}.get(selector, str(selector))
    matching_name = {0: "Full", 1: "SHA-256", 2: "SHA-512"}.get(matching, str(matching))
    label = (
        f"{usage_name}({usage}) {selector_name}({selector}) {matching_name}({matching})"
    )

    computed = _tlsa_fingerprint(cert_der, selector, matching)
    if computed is None:
        return False, f"{label}: fingerprint type not supported"
    if computed == dns_hex:
        return True, f"{label}: fingerprint matches ✔"
    return False, (
        f"{label}: fingerprint MISMATCH – DNS: {dns_hex[:32]}… / cert: {computed[:32]}…"
    )


def _fetch_cert_der(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
) -> bytes | None:  # pragma: no cover
    """Open a fresh STARTTLS connection and return the raw DER certificate.

    Used as a fallback when :func:`_probe_tls` did not store the DER (e.g.
    STARTTLS was not advertised during the main probe).

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :returns: Raw DER bytes, or ``None`` on any failure.
    :rtype: bytes or None
    """
    try:
        smtp, _, _ = _connect_plain(host, port)
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return None
        ctx = _no_verify_ctx()
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        der = smtp.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
        try:
            smtp.quit()
        except Exception:
            pass
        return der
    except Exception:
        return None


def _check_dane(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    cert_der: bytes | None,
    checks: list[CheckResult],
) -> None:
    """Look up TLSA records and verify them against the live server certificate.

    DANE usages for MX servers (RFC 7672):

    - Usage 2 (``DANE-TA``) – trust anchor; certificate must chain to this record.
    - Usage 3 (``DANE-EE``) – end entity; certificate must match this record exactly.

    Usages 0 (``PKIX-TA``) and 1 (``PKIX-EE``) are PKIX-constrained; they are
    flagged as warnings rather than errors.

    DANE allows multiple TLSA records so that the next certificate can be
    pre-published before the current one expires.  Non-matching records during
    a valid rollover are expected and noted as informational.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port (used to form the TLSA owner name ``_<port>._tcp.<host>``).
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param cert_der: DER-encoded certificate stashed by :func:`_probe_tls`,
        or ``None`` to trigger a fresh fetch.
    :type cert_der: bytes or None
    :param checks: List to which :class:`~mailcheck.models.CheckResult`
        items are appended.
    :type checks: list[~mailcheck.models.CheckResult]
    """
    tlsa_name = f"_{port}._tcp.{host}"
    records = resolve(tlsa_name, "TLSA")

    if not records:
        checks.append(
            CheckResult(
                name="DANE – TLSA Existence",
                status=Status.INFO,
                details=[f"No TLSA record at {tlsa_name}. DANE is not configured."],
            )
        )
        return

    recommended = [r for r in records if r.startswith("2 ") or r.startswith("3 ")]
    pkix_only = [r for r in records if r.startswith("0 ") or r.startswith("1 ")]

    checks.append(
        CheckResult(
            name="DANE – TLSA Existence",
            status=Status.OK if recommended else Status.WARNING,
            value=f"{len(records)} TLSA record(s), {len(recommended)} with recommended usage",
            details=(
                recommended + pkix_only
                if recommended
                else [
                    "Only PKIX-TA(0)/PKIX-EE(1) usages found; "
                    "DANE-TA(2) or DANE-EE(3) are required for MX servers (RFC 7672)."
                ]
            ),
        )
    )

    if not recommended:
        return

    # Certificate fingerprint verification
    der = cert_der or _fetch_cert_der(host, port, helo_domain, sni_hostname)

    if der is None:
        checks.append(
            CheckResult(
                name="DANE – Certificate Match",
                status=Status.WARNING,
                details=[
                    "Could not retrieve the server certificate; TLSA fingerprints unverified."
                ],
            )
        )
    else:
        results = [_verify_tlsa_record(r, der) for r in recommended]
        n_match = sum(ok for ok, _ in results)
        detail_lines = [desc for _, desc in results]

        if n_match > 0:
            if n_match < len(results):
                detail_lines.append(
                    f"{len(results) - n_match} non-matching record(s) appear to be pre-published "
                    "for the next certificate (rollover) — this is expected and correct."
                )
            checks.append(
                CheckResult(
                    name="DANE – Certificate Match",
                    status=Status.OK,
                    value=f"{n_match}/{len(results)} record(s) match",
                    details=detail_lines,
                )
            )
        else:
            detail_lines.append(
                "No TLSA record matches the server certificate. "
                "DANE-aware senders will reject mail from this server."
            )
            checks.append(
                CheckResult(
                    name="DANE – Certificate Match",
                    status=Status.ERROR,
                    value=f"0/{len(results)} records match",
                    details=detail_lines,
                )
            )

    # Rollover scheme assessment
    n_ee = sum(1 for r in recommended if r.startswith("3 "))
    n_ta = sum(1 for r in recommended if r.startswith("2 "))

    if len(recommended) >= 2:
        if n_ee >= 1 and n_ta >= 1:
            note, status = (
                "DANE-EE + DANE-TA (current cert + issuer CA) – recommended rollover scheme.",
                Status.OK,
            )
        elif n_ee >= 2:
            note, status = (
                "DANE-EE + DANE-EE (current + next cert) – recommended rollover scheme.",
                Status.OK,
            )
        else:
            note, status = (
                "Non-standard type combination; verify your rollover plan.",
                Status.WARNING,
            )
    else:
        note, status = (
            "Only one TLSA record present. Add a second record (next cert or issuer CA) for a safe rollover.",
            Status.WARNING,
        )

    checks.append(
        CheckResult(name="DANE – Rollover Scheme", status=status, details=[note])
    )


# ---------------------------------------------------------------------------
# Open relay test
# ---------------------------------------------------------------------------


def _test_open_relay(smtp: smtplib.SMTP, helo_domain: str) -> bool:  # pragma: no cover
    """Return ``True`` if the server relays mail for two unrelated external addresses.

    Issues ``MAIL FROM`` and ``RCPT TO`` for addresses at distinct
    ``*.example`` domains.  If both return SMTP 250 the server is an open
    relay.  ``RSET`` is always sent to avoid leaving a partial transaction
    queued on the server.

    :param smtp: Active :class:`smtplib.SMTP` connection.
    :type smtp: smtplib.SMTP
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :rtype: bool
    """
    try:
        smtp.ehlo(helo_domain)
        code, _ = smtp.mail("relay-test@external-domain-test.example")
        if code != 250:
            return False
        code, _ = smtp.rcpt("relay-test@another-external-domain.example")
        try:
            smtp.rset()
        except smtplib.SMTPException:
            pass
        return code == 250
    except smtplib.SMTPException:
        return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_smtp(
    host: str,
    port: int = 25,
    helo_domain: str = "mailcheck.local",
) -> SMTPDiagResult:  # pragma: no cover
    """Run all SMTP diagnostics for *host*:*port* and return a populated result.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: TCP port to probe.  Defaults to ``25``.
    :type port: int
    :param helo_domain: Domain name sent in the EHLO greeting.
        Defaults to ``"mailcheck.local"``.
    :type helo_domain: str
    :returns: A fully populated :class:`~mailcheck.models.SMTPDiagResult`.
    :rtype: ~mailcheck.models.SMTPDiagResult
    """
    result = SMTPDiagResult(host=host, port=port)

    # Resolve to IP for PTR lookup (non-fatal; fall back to host string)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ip = host

    # Connect
    try:
        smtp, connect_ms, banner = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException) as exc:
        result.checks.append(
            CheckResult(
                name="SMTP Connect",
                status=Status.ERROR,
                details=[f"Could not connect to {host}:{port} – {exc}"],
            )
        )
        return result

    result.response_time_ms = round(connect_ms, 2)
    result.banner = banner
    result.checks.append(
        CheckResult(
            name="SMTP Connect",
            status=Status.OK,
            value=f"{connect_ms:.1f} ms",
            details=[f"Banner: {banner}"],
        )
    )

    # Reverse DNS (PTR)
    ptr = reverse_lookup(ip)
    result.reverse_dns = ptr
    result.checks.append(
        CheckResult(
            name="Reverse DNS (PTR)",
            status=Status.OK if ptr else Status.WARNING,
            value=ptr or "",
            details=(
                [f"{ip} → {ptr}"]
                if ptr
                else [
                    f"No PTR record for {ip}. Many servers reject mail from IPs without reverse DNS."
                ]
            ),
        )
    )

    # EHLO + STARTTLS advertisement
    try:
        smtp.ehlo(helo_domain)
        has_starttls = smtp.has_extn("STARTTLS")
    except smtplib.SMTPException:
        has_starttls = False

    result.tls_supported = has_starttls
    result.checks.append(
        CheckResult(
            name="STARTTLS",
            status=Status.OK if has_starttls else Status.WARNING,
            details=(
                ["STARTTLS advertised."]
                if has_starttls
                else [
                    "STARTTLS is NOT advertised. Mail may be transmitted in plaintext."
                ]
            ),
        )
    )

    # Open relay
    open_relay = _test_open_relay(smtp, helo_domain)
    result.open_relay = open_relay
    result.checks.append(
        CheckResult(
            name="Open Relay",
            status=Status.ERROR if open_relay else Status.OK,
            details=(
                [
                    "Server accepts relaying for external addresses — critical misconfiguration."
                ]
                if open_relay
                else ["Server correctly rejects open relay attempts."]
            ),
        )
    )

    try:
        smtp.quit()
    except smtplib.SMTPException:
        pass

    # Deep TLS inspection (separate connection)
    sni_hostname: str | None = None
    if has_starttls:
        tls_details, tls_err, sni_hostname = _probe_tls(host, port, helo_domain)
        if tls_err:
            result.checks.append(
                CheckResult(
                    name="TLS Inspection",
                    status=Status.ERROR,
                    details=[f"TLS probe failed: {tls_err}"],
                )
            )
        else:
            result.tls = tls_details
            assert tls_details is not None  # narrow type for static checker
            _check_tls_version(
                host, port, helo_domain, sni_hostname, tls_details, result.checks
            )
            _check_cipher(
                host, port, helo_domain, sni_hostname, tls_details, result.checks
            )
            _check_cipher_order(
                host, port, helo_domain, sni_hostname, tls_details, result.checks
            )
            _check_key_exchange(tls_details, result.checks)
            _check_hash_function(tls_details, result.checks)
            _check_compression(tls_details, result.checks)
            _check_renegotiation(tls_details, result.checks)
            _check_certificate(tls_details, result.checks, host)

    # CAA
    _check_caa(host, result.checks)

    # DANE – reuse the DER stashed by _probe_tls to avoid an extra connection.
    cert_der = (
        result.tls._cert_der  # type: ignore[attr-defined]
        if result.tls and hasattr(result.tls, "_cert_der")
        else None
    )
    _check_dane(host, port, helo_domain, sni_hostname, cert_der, result.checks)

    return result
