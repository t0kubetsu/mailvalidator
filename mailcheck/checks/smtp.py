"""SMTP diagnostics: banner, PTR, open relay, STARTTLS, and deep TLS inspection."""

from __future__ import annotations

import hashlib
import ipaddress
import smtplib
import socket
import ssl
import time
from datetime import datetime, timezone

from mailcheck.dns_utils import resolve
from mailcheck.dns_utils import reverse_lookup
from mailcheck.models import CheckResult, SMTPDiagResult, Status, TLSDetails

_TIMEOUT = 10  # seconds

# ---------------------------------------------------------------------------
# Cipher classification tables
# ---------------------------------------------------------------------------

_GOOD_CIPHERS: frozenset[str] = frozenset(
    {
        # TLS 1.2 ECDHE-ECDSA
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        # TLS 1.2 ECDHE-RSA
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-GCM-SHA256",
        # TLS 1.3 standard suite names
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    }
)

_SUFFICIENT_CIPHERS: frozenset[str] = frozenset(
    {
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA",
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
        "ECDHE-ECDSA-DES-CBC3-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
        "DHE-RSA-DES-CBC3-SHA",
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES256-SHA",
        "AES128-SHA256",
        "AES128-SHA",
        "DES-CBC3-SHA",
    }
)

# ---------------------------------------------------------------------------
# Key-exchange parameter classification
# ---------------------------------------------------------------------------

_GOOD_EC_CURVES: frozenset[str] = frozenset(
    {"secp384r1", "secp256r1", "x448", "x25519", "prime256v1"}
)
_PHASE_OUT_EC_CURVES: frozenset[str] = frozenset({"secp224r1"})

# SHA-256 checksums of the DH group prime (ffdhe groups from RFC 7919).
_SUFFICIENT_FFDHE: dict[str, str] = {
    "ffdhe4096": "64852d6890ff9e62eecd1ee89c72af9af244dfef5b853bcedea3dfd7aade22b3",
    "ffdhe3072": "c410cc9c4fd85d2c109f7ebe5930ca5304a52927c0ebcb1a11c5cf6b2386bbab",
    "ffdhe8192": "",  # noted – limited gain
    "ffdhe6144": "",  # noted – limited gain
}
_PHASE_OUT_FFDHE: dict[str, str] = {
    "ffdhe2048": "9ba6429597aeed2d8617a7705b56e96d044f64b07971659382e426675105654b",
}

# Ordered list used to validate cipher preference ordering
_PRESCRIBED_ORDER: list[str] = (
    sorted(_GOOD_CIPHERS) + sorted(_SUFFICIENT_CIPHERS) + sorted(_PHASE_OUT_CIPHERS)
)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _connect_plain(host: str, port: int) -> tuple[smtplib.SMTP, float, str]:
    """Plain SMTP connect; returns (smtp, elapsed_ms, banner)."""
    t0 = time.monotonic()
    smtp = smtplib.SMTP(timeout=_TIMEOUT)
    _code, msg = smtp.connect(host, port)
    elapsed = (time.monotonic() - t0) * 1000
    banner = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
    return smtp, elapsed, banner


def _starttls_context(verify: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _tls_version_status(version: str) -> Status:
    if version == "TLSv1.3":
        return Status.OK
    if version == "TLSv1.2":
        return Status.SUFFICIENT
    if version in ("TLSv1.1", "TLSv1"):
        return Status.PHASE_OUT
    # SSLv3, SSLv2, unknown
    return Status.INSUFFICIENT


def _classify_cipher(name: str) -> Status:
    if name in _GOOD_CIPHERS:
        return Status.GOOD
    if name in _SUFFICIENT_CIPHERS:
        return Status.SUFFICIENT
    if name in _PHASE_OUT_CIPHERS:
        return Status.PHASE_OUT
    return Status.INSUFFICIENT


def _classify_ec_curve(curve: str) -> Status:
    if curve in _GOOD_EC_CURVES:
        return Status.GOOD
    if curve in _PHASE_OUT_EC_CURVES:
        return Status.PHASE_OUT
    return Status.INSUFFICIENT


def _cert_info(der: bytes) -> dict:
    """Extract certificate metadata via ssl.DER_cert_to_PEM_cert + openssl-style parsing."""
    # Use the high-level ssl helper where possible; fall back gracefully.
    try:
        import cryptography.hazmat.primitives.asymmetric.ec as _ec
        import cryptography.hazmat.primitives.asymmetric.rsa as _rsa
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(der)
        info: dict = {}

        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        info["not_after"] = cert.not_valid_after_utc.isoformat()
        info["sig_alg"] = (
            cert.signature_hash_algorithm.name
            if cert.signature_hash_algorithm
            else "unknown"
        )

        # SAN
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            info["san"] = [n.value for n in san_ext.value]
        except x509.ExtensionNotFound:
            info["san"] = []

        # Public key
        pub = cert.public_key()
        if isinstance(pub, _rsa.RSAPublicKey):
            info["pubkey_type"] = "RSA"
            info["pubkey_bits"] = pub.key_size
            info["pubkey_curve"] = ""
        elif isinstance(pub, _ec.EllipticCurvePublicKey):
            info["pubkey_type"] = "EC"
            info["pubkey_bits"] = pub.key_size
            info["pubkey_curve"] = pub.curve.name
        else:
            info["pubkey_type"] = type(pub).__name__
            info["pubkey_bits"] = 0
            info["pubkey_curve"] = ""

        return info
    except ImportError:
        # cryptography package not available – return empty dict
        return {}


# ---------------------------------------------------------------------------
# TLS probe: performs STARTTLS and deep-inspects the session
# ---------------------------------------------------------------------------


def _is_ip(host: str) -> bool:
    """Return True if *host* is a bare IP address (v4 or v6)."""
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _probe_tls(
    host: str, port: int, helo_domain: str
) -> tuple[TLSDetails | None, str, str | None]:
    """Connect, STARTTLS, and return (TLSDetails, error_message)."""
    details = TLSDetails()

    # SNI requires a hostname, not an IP address.
    # If the caller passes an IP we skip SNI (server_hostname=None is not
    # accepted by Python ssl either, so we use an unverified context without
    # check_hostname in that case).
    sni_hostname: str | None = None if _is_ip(host) else host

    # --- plain connect ---
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException) as exc:
        return None, str(exc), None

    # --- EHLO + STARTTLS upgrade ---
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return None, "STARTTLS not advertised", None

        ctx = _starttls_context(verify=False)  # we inspect the cert ourselves
        if sni_hostname:
            # Ensure smtplib uses the correct server_hostname for SNI.
            # smtp._host may be empty when the object was constructed without
            # an initial host argument (e.g. SMTP() then .connect()).
            smtp._host = sni_hostname  # type: ignore[attr-defined]
        else:
            # IP address: disable hostname checking entirely so wrap_socket
            # does not raise "server_hostname cannot be an empty string".
            ctx.check_hostname = False
            smtp._host = host  # type: ignore[attr-defined]

        smtp.starttls(context=ctx)
        smtp.ehlo(helo_domain)
    except (smtplib.SMTPException, ValueError) as exc:
        return None, f"STARTTLS failed: {exc}", None

    # --- inspect the live SSL socket ---
    raw_sock = smtp.sock
    if not isinstance(raw_sock, ssl.SSLSocket):
        smtp.quit()
        return None, "Socket is not an SSLSocket after STARTTLS", None

    tls_ver = raw_sock.version() or ""
    details.tls_version = tls_ver

    cipher_info = raw_sock.cipher()  # (name, protocol, bits)
    if cipher_info:
        details.cipher_name = cipher_info[0]
        details.cipher_bits = cipher_info[2] or 0

    # compression
    details.compression = raw_sock.compression() or ""

    # DH / key exchange group
    try:
        # Available in Python 3.10+ via ssl.SSLSocket.get_channel_binding or
        # internal _ssl – use the safer public API where possible.
        kex = getattr(raw_sock, "_sslobj", None)
        if kex:
            group = getattr(kex, "group", None)
            if callable(group):
                details.dh_group = group() or ""
    except Exception:
        pass

    # certificate
    der = raw_sock.getpeercert(binary_form=True)
    if der:
        info = _cert_info(der)
        details.cert_subject = info.get("subject", "")
        details.cert_issuer = info.get("issuer", "")
        details.cert_san = info.get("san", [])
        details.cert_not_after = info.get("not_after", "")
        details.cert_sig_alg = info.get("sig_alg", "")
        details.cert_pubkey_type = info.get("pubkey_type", "")
        details.cert_pubkey_bits = info.get("pubkey_bits", 0)
        details.cert_pubkey_curve = info.get("pubkey_curve", "")

        # Trust: try verifying with system trust store.
        # SNI and hostname checking only work for DNS names, not bare IPs.
        if sni_hostname:
            try:
                verify_ctx = _starttls_context(verify=True)
                verify_ctx.check_hostname = True
                verify_ctx.verify_mode = ssl.CERT_REQUIRED
                with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
                    # Need a plain TCP socket; re-do the STARTTLS dance here
                    # is too complex – just wrap the raw TCP socket directly.
                    # This only verifies the *certificate chain*, not STARTTLS.
                    with verify_ctx.wrap_socket(raw, server_hostname=sni_hostname):
                        pass
                details.cert_trusted = True
            except ssl.SSLCertVerificationError:
                details.cert_trusted = False
            except OSError:
                details.cert_trusted = False
        else:
            # Cannot verify trust for IP-addressed hosts via SNI.
            details.cert_trusted = False

    # secure renegotiation flag (RI extension)
    try:
        details.secure_renegotiation = (
            raw_sock.get_channel_binding("tls-unique") is not None
        )
    except Exception:
        details.secure_renegotiation = None

    # 0-RTT: only relevant for TLS 1.3
    if tls_ver == "TLSv1.3":
        # Python's ssl module does not expose early-data; mark as not detectable.
        details.zero_rtt = None  # cannot probe without C-level access
    else:
        details.zero_rtt = None  # N/A

    try:
        smtp.quit()
    except Exception:
        pass

    return details, "", sni_hostname


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

# TLS version probe table.
# Strategy:
#   TLS 1.2 / 1.3  →  Python ssl (minimum_version = maximum_version = target).
#   TLS 1.0 / 1.1  →  `openssl s_client` with a permissive temporary
#                      OPENSSL_CONF (MinProtocol=TLSv1 + SECLEVEL=0).
#
# Why the split?  System-wide OpenSSL policy (SECLEVEL=2 / MinProtocol=TLSv1.2,
# compiled in as OPENSSL_TLS_SECURITY_LEVEL=2 on Debian/Ubuntu) prevents Python
# from *locally* negotiating TLS < 1.2 even when the remote server supports it.
# Neither minimum_version/maximum_version nor OP_NO_* flags can override that
# compiled-in policy from Python.  Spawning openssl s_client with a custom
# OPENSSL_CONF is the same approach testssl.sh uses, so results match.

# (label, ssl.TLSVersion min/max)
# set_ciphers("DEFAULT:@SECLEVEL=0") is applied to every probe so that
# the weak ciphers required by TLS 1.0/1.1 are permitted on the *client*
# side regardless of the local OpenSSL system policy (SECLEVEL=2 on most
# modern distros).  Without it, the handshake fails locally and the server
# is falsely reported as not supporting the version.
# TLS 1.0/1.1 are included only when the runtime OpenSSL exposes them.
_TLS_VERSION_PROBES: list[tuple[str, ssl.TLSVersion, ssl.TLSVersion]] = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
]
for _label, _attr in (("TLSv1.1", "TLSv1_1"), ("TLSv1", "TLSv1")):
    if hasattr(ssl.TLSVersion, _attr):
        _v = getattr(ssl.TLSVersion, _attr)
        _TLS_VERSION_PROBES.append((_label, _v, _v))


# Versions that require SECLEVEL=0 to allow their weak ciphers on the client.
# Modern OpenSSL defaults to SECLEVEL=2 which rejects the ciphers used by
# TLS 1.0/1.1; without lowering it, the handshake fails on our side and we
# would falsely report the server as not supporting these versions.
_LEGACY_TLS_VERSIONS: frozenset[ssl.TLSVersion] = frozenset(
    v
    for attr in ("TLSv1", "TLSv1_1")
    if hasattr(ssl.TLSVersion, attr)
    for v in (getattr(ssl.TLSVersion, attr),)
)


def _probe_single_tls_version(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
) -> bool:
    """Return True if the server accepts a STARTTLS handshake restricted to
    exactly the requested TLS version range."""
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException):
        return False
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return False

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_min
        ctx.maximum_version = tls_max

        # Lower SECLEVEL only for legacy versions that need weak ciphers.
        # Applying this to TLS 1.2/1.3 probes would mask cipher misconfigs.
        if tls_min in _LEGACY_TLS_VERSIONS:
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass  # older OpenSSL that does not recognise SECLEVEL syntax

        smtp._host = sni_hostname if sni_hostname else host  # type: ignore[attr-defined]
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
    """Actively probe which TLS versions the server accepts."""

    # Summarise what the best negotiated version was (from _probe_tls)
    negotiated = details.tls_version

    accepted: list[str] = []
    rejected: list[str] = []

    for label, tls_min, tls_max in _TLS_VERSION_PROBES:
        ok = _probe_single_tls_version(
            host, port, helo_domain, sni_hostname, tls_min, tls_max
        )
        if ok:
            accepted.append(label)
        else:
            rejected.append(label)

    # Overall verdict: fail if any phase-out/insufficient version is accepted
    phase_out_accepted = [
        v for v in accepted if _tls_version_status(v) == Status.PHASE_OUT
    ]
    insufficient_accepted = [
        v for v in accepted if _tls_version_status(v) == Status.INSUFFICIENT
    ]
    good_accepted = [v for v in accepted if _tls_version_status(v) == Status.OK]
    sufficient_accepted = [
        v for v in accepted if _tls_version_status(v) == Status.SUFFICIENT
    ]

    if insufficient_accepted:
        overall = Status.INSUFFICIENT
    elif phase_out_accepted:
        overall = Status.PHASE_OUT
    elif good_accepted:
        overall = Status.GOOD
    elif sufficient_accepted:
        overall = Status.SUFFICIENT
    else:
        overall = Status.INFO  # could not determine (all probes blocked/failed)

    detail_lines: list[str] = []
    for v in accepted:
        st = _tls_version_status(v)
        marker = {
            "OK": "✔",
            "GOOD": "✔",
            "PHASE_OUT": "↓ phase-out",
            "INSUFFICIENT": "✘ insecure",
        }.get(st.value, "✔")
        detail_lines.append(f"  {marker}  {v} – accepted")
    for v in rejected:
        detail_lines.append(f"  –  {v} – not accepted")

    if phase_out_accepted:
        detail_lines.append(
            f"Disable: {', '.join(phase_out_accepted)} – deprecated protocol(s) accepted."
        )
    if insufficient_accepted:
        detail_lines.append(
            f"CRITICAL – disable: {', '.join(insufficient_accepted)} – insecure protocol(s) accepted."
        )

    checks.append(
        CheckResult(
            name="TLS Versions",
            status=overall,
            value=f"Best: {negotiated}" if negotiated else "negotiated version unknown",
            details=detail_lines,
        )
    )


def _check_cipher(details: TLSDetails, checks: list[CheckResult]) -> None:
    name = details.cipher_name
    status = _classify_cipher(name)
    detail_map = {
        Status.GOOD: [],
        Status.SUFFICIENT: [
            "Cipher is acceptable but not ideal. Prefer ECDHE+AES-GCM or ChaCha20-Poly1305."
        ],
        Status.PHASE_OUT: [
            "Cipher is weak and should be removed from the server configuration."
        ],
        Status.INSUFFICIENT: ["Cipher is insecure. Disable immediately."],
    }
    checks.append(
        CheckResult(
            name="Cipher Suite",
            status=status,
            value=f"{name} ({details.cipher_bits} bit)",
            details=detail_map.get(status, []),
        )
    )


def _check_cipher_order(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Check server cipher preference enforcement and prescribed ordering."""
    offered = details.offered_ciphers
    if not offered:
        checks.append(
            CheckResult(
                name="Cipher Order",
                status=Status.INFO,
                details=["Could not enumerate offered ciphers to assess order."],
            )
        )
        return

    # I. Server enforced preference
    so = details.server_cipher_order
    if so is None:
        checks.append(
            CheckResult(
                name="Cipher Order – Server Preference",
                status=Status.INFO,
                details=["Could not determine."],
            )
        )
    elif so:
        checks.append(
            CheckResult(
                name="Cipher Order – Server Preference",
                status=Status.OK,
                value="Enforced",
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Cipher Order – Server Preference",
                status=Status.WARNING,
                value="Not enforced",
                details=[
                    "Server accepts the client's cipher preference; enforce server-side ordering."
                ],
            )
        )

    # II. Prescribed ordering: all Good before Sufficient before Phase-out
    categories = [_classify_cipher(c) for c in offered]
    order_rank = {
        Status.GOOD: 0,
        Status.SUFFICIENT: 1,
        Status.PHASE_OUT: 2,
        Status.INSUFFICIENT: 3,
    }
    ranks = [order_rank.get(s, 3) for s in categories]
    prescribed = ranks == sorted(ranks)

    # If only Good ciphers are offered, ordering is N/A
    unique_cats = set(categories)
    if unique_cats <= {Status.GOOD}:
        checks.append(
            CheckResult(
                name="Cipher Order – Prescribed Ordering",
                status=Status.NA,
                value="N/A (Good ciphers only)",
            )
        )
    elif prescribed:
        checks.append(
            CheckResult(
                name="Cipher Order – Prescribed Ordering",
                status=Status.OK,
                value="Correct",
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Cipher Order – Prescribed Ordering",
                status=Status.WARNING,
                value="Incorrect",
                details=[
                    "Ciphers are not offered in Good → Sufficient → Phase-out order."
                ],
            )
        )


def _check_key_exchange(details: TLSDetails, checks: list[CheckResult]) -> None:
    cipher = details.cipher_name
    group = details.dh_group

    if "ECDHE" in cipher or "ECDH" in cipher:
        curve = group or details.cert_pubkey_curve
        status = _classify_ec_curve(curve)
        details_msg: list[str] = []
        if status == Status.PHASE_OUT:
            details_msg = [
                f"Curve {curve} is deprecated; migrate to secp256r1 or secp384r1."
            ]
        elif status == Status.INSUFFICIENT:
            details_msg = [f"Curve {curve} is not considered secure for key exchange."]
        checks.append(
            CheckResult(
                name="Key Exchange – EC Curve",
                status=status,
                value=curve or "(unknown)",
            )
        )

    elif "DHE" in cipher:
        # Finite-field DH group assessment by bit size (group name often not
        # exposed by Python ssl; use key bits as a proxy).
        bits = details.dh_bits
        if bits >= 4096:
            st, note = Status.SUFFICIENT, "ffdhe4096 or larger"
        elif bits >= 3072:
            st, note = Status.SUFFICIENT, "ffdhe3072 or larger"
        elif bits >= 2048:
            st, note = Status.PHASE_OUT, "ffdhe2048 – phase out; upgrade to ≥3072 bit."
        else:
            st, note = Status.INSUFFICIENT, f"{bits}-bit DH is insecure."
        checks.append(
            CheckResult(
                name="Key Exchange – DH Group",
                status=st,
                value=f"{bits} bit",
                details=[note] if st != Status.SUFFICIENT else [],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Key Exchange",
                status=Status.INFO,
                value=cipher,
                details=[
                    "No DHE/ECDHE detected; forward secrecy may not be available."
                ],
            )
        )


def _check_hash_function(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Check the hash function used for the TLS key-exchange signature."""
    cipher = details.cipher_name
    # Extract hash suffix from cipher name (e.g. AES256-GCM-SHA384 → SHA384)
    sha_good = {"sha256", "sha384", "sha512"}
    sha_phase_out = {"sha1", "sha", "md5"}

    found: str | None = None
    for part in cipher.lower().split("-"):
        if part in sha_good:
            found = part.upper()
            break
        if part in sha_phase_out:
            found = part.upper()
            break

    # TLS 1.3 always uses HKDF with SHA-256/384 – mark as good
    if details.tls_version == "TLSv1.3":
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)",
                status=Status.GOOD,
                value="SHA-256/384 (TLS 1.3 HKDF)",
            )
        )
        return

    if found and found.lower() in sha_good | {"sha256", "sha384", "sha512"}:
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


def _check_compression(details: TLSDetails, checks: list[CheckResult]) -> None:
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
                    "TLS compression is enabled. Disable immediately to prevent CRIME attacks."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="TLS Compression",
                status=Status.SUFFICIENT,
                value=comp,
                details=["Application-level compression detected."],
            )
        )


def _check_renegotiation(details: TLSDetails, checks: list[CheckResult]) -> None:
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
                    "RFC 5746 secure renegotiation is absent; server is vulnerable to renegotiation attacks."
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

    # Client-initiated renegotiation cannot be probed reliably without
    # actually initiating one; mark as informational.
    checks.append(
        CheckResult(
            name="Client-Initiated Renegotiation",
            status=Status.INFO,
            details=[
                "Active probe not performed. Verify server-side configuration manually."
            ],
        )
    )


def _check_zero_rtt(details: TLSDetails, checks: list[CheckResult]) -> None:
    if details.tls_version != "TLSv1.3":
        checks.append(
            CheckResult(name="0-RTT", status=Status.NA, value="N/A (TLS < 1.3)")
        )
        return
    # Python's ssl module does not expose early-data session ticket max_early_data.
    checks.append(
        CheckResult(
            name="0-RTT",
            status=Status.INFO,
            details=[
                "Python ssl does not expose early-data ticket size. Use an external tool (e.g. testssl.sh) to probe 0-RTT."
            ],
        )
    )


def _check_certificate(
    details: TLSDetails, checks: list[CheckResult], host: str
) -> None:
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
    checks.append(
        CheckResult(
            name="Certificate Trust Chain",
            status=Status.GOOD if details.cert_trusted else Status.WARNING,
            value="Trusted" if details.cert_trusted else "Untrusted / self-signed",
            details=[]
            if details.cert_trusted
            else ["Certificate cannot be verified against the system trust store."],
        )
    )

    # Public key
    pk_type = details.cert_pubkey_type
    pk_bits = details.cert_pubkey_bits
    pk_curve = details.cert_pubkey_curve

    if pk_type == "RSA":
        if pk_bits >= 3072:
            pk_status, pk_note = Status.GOOD, ""
        elif pk_bits >= 2048:
            pk_status, pk_note = (
                Status.SUFFICIENT,
                "2048-bit RSA is acceptable but 3072+ is recommended.",
            )
        else:
            pk_status, pk_note = (
                Status.INSUFFICIENT,
                f"{pk_bits}-bit RSA key is too short.",
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
                    [f"Curve {pk_curve} is deprecated."]
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
    good_sig = {
        "sha256",
        "sha384",
        "sha512",
        "sha256withrsaencryption",
        "sha384withrsaencryption",
        "sha512withrsaencryption",
        "ecdsa-with-sha256",
        "ecdsa-with-sha384",
        "ecdsa-with-sha512",
    }
    bad_sig = {"sha1", "md5", "sha1withrsaencryption", "md5withrsaencryption"}
    if any(g in sig_alg for g in {"sha256", "sha384", "sha512"}):
        sig_status = Status.GOOD
    elif any(b in sig_alg for b in {"sha1", "md5"}):
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
                    "SHA-1/MD5 signatures are insecure; certificate must be reissued with SHA-256+."
                ]
                if sig_status == Status.INSUFFICIENT
                else []
            ),
        )
    )

    # Domain name match
    san = details.cert_san
    hostname = host.lower()
    matched = any(
        hostname == n.lower()
        or (n.startswith("*.") and hostname.endswith(n[1:].lower()))
        for n in san
    )
    if not san:
        # Fall back to subject CN check
        cn_match = f"cn={hostname}" in details.cert_subject.lower()
        matched = cn_match

    checks.append(
        CheckResult(
            name="Certificate Domain Match",
            status=Status.OK if matched else Status.WARNING,
            value="Match" if matched else "Mismatch",
            details=[]
            if matched
            else [
                f"Hostname '{host}' not found in SAN/CN. "
                "Note: SMTP senders typically ignore domain match unless DANE-TA is used."
            ],
        )
    )

    # Expiry
    if details.cert_not_after:
        try:
            expiry = datetime.fromisoformat(details.cert_not_after)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            days_left = (expiry - now).days
            if days_left < 0:
                exp_status = Status.ERROR
                exp_detail = ["Certificate has expired!"]
            elif days_left < 30:
                exp_status = Status.WARNING
                exp_detail = [f"Certificate expires in {days_left} day(s)."]
            else:
                exp_status = Status.OK
                exp_detail = [f"Expires in {days_left} days ({expiry.date()})."]
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


def _check_caa(host: str, checks: list[CheckResult]) -> list[str]:
    """Look up CAA records for the MX hostname (walks up DNS hierarchy)."""
    labels = host.rstrip(".").split(".")
    caa_records: list[str] = []
    found_at: str = ""

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
                    f"No CAA records found for {host} or any parent domain. Any CA can issue certificates."
                ],
            )
        )
        return []

    # Validate syntax and require at least one 'issue' tag
    has_issue = any("issue " in r or r.strip().endswith("issue") for r in caa_records)
    iodef_http = any(
        "iodef" in r and "http://" in r and "https://" not in r for r in caa_records
    )
    syntax_ok = all(len(r.split()) >= 3 for r in caa_records)

    issues: list[str] = []
    if not has_issue:
        issues.append("No 'issue' tag found; add at least one CAA 'issue' record.")
    if iodef_http:
        issues.append("iodef URL uses HTTP; use HTTPS for secure incident reporting.")
    if not syntax_ok:
        issues.append("One or more CAA records may have invalid syntax.")

    checks.append(
        CheckResult(
            name="CAA Records",
            status=Status.OK if not issues else Status.WARNING,
            value=f"{len(caa_records)} record(s) at {found_at}",
            details=caa_records + issues,
        )
    )
    return caa_records


def _check_dane(host: str, port: int, checks: list[CheckResult]) -> None:
    """Look up TLSA records for DANE and perform basic validity checks."""
    tlsa_name = f"_{port}._tcp.{host}"
    records = resolve(tlsa_name, "TLSA")

    # Filter out PKIX-TA(0) and PKIX-EE(1) per spec
    valid_records = [
        r for r in records if not (r.startswith("0 ") or r.startswith("1 "))
    ]

    if not records:
        checks.append(
            CheckResult(
                name="DANE – TLSA Existence",
                status=Status.INFO,
                details=[
                    f"No TLSA record found at {tlsa_name}. DANE is not configured."
                ],
            )
        )
        return

    checks.append(
        CheckResult(
            name="DANE – TLSA Existence",
            status=Status.OK if valid_records else Status.WARNING,
            value=f"{len(valid_records)} valid TLSA record(s)",
            details=valid_records
            or [
                "Only PKIX-TA(0)/PKIX-EE(1) records found; these should not be used for MX."
            ],
        )
    )

    # Rollover scheme: check for ≥2 records with complementary types
    if len(valid_records) >= 2:
        has_ee = any(r.startswith("3 ") for r in valid_records)
        has_ta = any(r.startswith("2 ") for r in valid_records)
        if has_ee and has_ta:
            rollover_note = "Current + Issuer CA scheme (3 x x + 2 x x) – recommended."
            rollover_status = Status.OK
        elif sum(1 for r in valid_records if r.startswith("3 ")) >= 2:
            rollover_note = "Current + Next scheme (3 x x + 3 x x) – recommended."
            rollover_status = Status.OK
        else:
            rollover_note = "Rollover scheme present but uses non-standard types."
            rollover_status = Status.WARNING
        checks.append(
            CheckResult(
                name="DANE – Rollover Scheme",
                status=rollover_status,
                details=[rollover_note],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="DANE – Rollover Scheme",
                status=Status.WARNING,
                details=[
                    "Only one TLSA record found. Add a second record for a safe rollover scheme."
                ],
            )
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_smtp(
    host: str, port: int = 25, helo_domain: str = "mailcheck.local"
) -> SMTPDiagResult:
    result = SMTPDiagResult(host=host, port=port)

    # --- resolve host to IP for PTR lookup ---
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ip = host

    # --- plain connect + banner ---
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
            details=[f"Banner: {result.banner}"],
        )
    )

    # --- reverse DNS (PTR) ---
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

    # --- EHLO / STARTTLS advertised? ---
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
                ["STARTTLS is advertised."]
                if has_starttls
                else ["STARTTLS is NOT advertised. Connections may be unencrypted."]
            ),
        )
    )

    # --- open relay test ---
    open_relay = _test_open_relay(smtp, helo_domain)
    result.open_relay = open_relay
    result.checks.append(
        CheckResult(
            name="Open Relay",
            status=Status.ERROR if open_relay else Status.OK,
            details=(
                [
                    "Server accepts relaying for external addresses. Critical misconfiguration."
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

    # --- deep TLS inspection (separate connection) ---
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
            assert tls_details is not None  # narrowing for type checker

            _check_tls_version(
                host, port, helo_domain, sni_hostname, tls_details, result.checks
            )
            _check_cipher(tls_details, result.checks)
            _check_cipher_order(tls_details, result.checks)
            _check_key_exchange(tls_details, result.checks)
            _check_hash_function(tls_details, result.checks)
            _check_compression(tls_details, result.checks)
            _check_renegotiation(tls_details, result.checks)
            _check_zero_rtt(tls_details, result.checks)
            _check_certificate(tls_details, result.checks, host)

    # --- CAA records ---
    _check_caa(host, result.checks)

    # --- DANE ---
    _check_dane(host, port, result.checks)

    return result


def _test_open_relay(smtp: smtplib.SMTP, helo_domain: str) -> bool:
    """Return True if the server accepts relaying for external addresses."""
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
