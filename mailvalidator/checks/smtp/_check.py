"""Public entry point for SMTP diagnostics: :func:`check_smtp`."""

from __future__ import annotations

import smtplib
import socket

from mailvalidator.dns_utils import reverse_lookup
from mailvalidator.models import CheckResult, SMTPDiagResult, Status

from ._cert import _check_certificate
from ._connection import _connect_plain
from ._dns import _check_caa, _check_dane
from ._protocol import _check_banner_fqdn, _check_ehlo_domain, _check_extensions, _check_vrfy, _test_open_relay
from ._tls_checks import (
    _check_cipher,
    _check_cipher_order,
    _check_compression,
    _check_hash_function,
    _check_key_exchange,
    _check_renegotiation,
    _check_tls_version,
)
from ._tls_probe import _probe_tls


def _tag(checks: list[CheckResult], start: int, section: str) -> None:
    """Tag all checks appended since *start* with *section*."""
    for cr in checks[start:]:
        cr.section = section


def check_smtp(
    host: str,
    port: int = 25,
    helo_domain: str = "mailvalidator.local",
) -> SMTPDiagResult:  # pragma: no cover
    """Run all SMTP diagnostics for *host*:*port* and return a populated result.

    This function targets **external-facing MX servers** (RFC 5321 §2.1).
    Port 25 is the standard MX port; port 587 is the submission port (RFC 6409)
    and is a different service — these checks are not appropriate against it.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: TCP port to probe.  Defaults to ``25`` (RFC 5321 §4.5.3.2).
    :type port: int
    :param helo_domain: Domain name sent in the EHLO greeting.
        Defaults to ``"mailvalidator.local"``.
    :type helo_domain: str
    :returns: A fully populated :class:`~mailvalidator.models.SMTPDiagResult`.
    :rtype: ~mailvalidator.models.SMTPDiagResult
    """
    result = SMTPDiagResult(host=host, port=port)

    # Resolve to IP for PTR lookup (non-fatal; fall back to host string)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ip = host

    # -------------------------------------------------------------------------
    # Protocol section
    # -------------------------------------------------------------------------
    proto_start = len(result.checks)

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
        _tag(result.checks, proto_start, "Protocol")
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

    # 220 banner FQDN validation (RFC 5321 §4.1.3)
    _check_banner_fqdn(banner, result.checks)

    # EHLO + STARTTLS advertisement
    try:
        smtp.ehlo(helo_domain)
        has_starttls = smtp.has_extn("STARTTLS")
    except smtplib.SMTPException:
        has_starttls = False

    # EHLO domain validation (RFC 5321 §4.1.1.1)
    _check_ehlo_domain(smtp, result.checks)

    # ESMTP extension advertisement (RFC 1870, RFC 2920, RFC 6152, RFC 6531)
    _check_extensions(smtp, result.checks)

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

    # VRFY command behaviour (RFC 5321 §3.5.3)
    _check_vrfy(smtp, helo_domain, result.checks)

    # Open relay (RFC 5321 §3.9)
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

    _tag(result.checks, proto_start, "Protocol")

    try:
        smtp.quit()
    except smtplib.SMTPException:
        pass

    # -------------------------------------------------------------------------
    # TLS section
    # -------------------------------------------------------------------------
    tls_start = len(result.checks)
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

    _tag(result.checks, tls_start, "TLS")

    # -------------------------------------------------------------------------
    # Certificate section
    # -------------------------------------------------------------------------
    cert_start = len(result.checks)
    if has_starttls and result.tls:
        _check_certificate(result.tls, result.checks, host)
    _tag(result.checks, cert_start, "Certificate")

    # -------------------------------------------------------------------------
    # DNS section
    # -------------------------------------------------------------------------
    dns_start = len(result.checks)

    # Reverse DNS (PTR) – DNS lookup, not a protocol property
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

    # CAA
    _check_caa(host, result.checks)

    # DANE – reuse the DER stashed by _probe_tls to avoid an extra connection.
    cert_der = (
        result.tls._cert_der  # type: ignore[attr-defined]
        if result.tls and hasattr(result.tls, "_cert_der")
        else None
    )
    _check_dane(host, port, helo_domain, sni_hostname, cert_der, result.checks)

    _tag(result.checks, dns_start, "DNS")

    return result
