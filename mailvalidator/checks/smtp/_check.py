"""Public entry point for SMTP diagnostics: :func:`check_smtp`."""

from __future__ import annotations

import smtplib
import socket

from mailvalidator.dns_utils import reverse_lookup
from mailvalidator.models import CheckResult, SMTPDiagResult, Status

from ._cert import _check_certificate
from ._connection import _connect_plain
from ._dns import _check_caa, _check_dane
from ._pqc import _check_pqc
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


_SMTP_FALLBACK_PORTS: tuple[int, ...] = (587, 465)


def _connect_or_fallback(
    host: str,
    port: int,
    fallback_ports: tuple[int, ...],
) -> tuple[smtplib.SMTP | None, float, str, int, str | None]:
    """Try *port* first; on refusal or timeout retry each port in *fallback_ports*.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: Primary TCP port to try.
    :type port: int
    :param fallback_ports: Additional ports to try after a refusal/timeout.
    :type fallback_ports: tuple[int, ...]
    :returns: ``(smtp, connect_ms, banner, actual_port, error)`` where *smtp* is
        ``None`` and *error* is a string when every attempt failed.
    :rtype: tuple[smtplib.SMTP | None, float, str, int, str | None]
    """
    try:
        smtp, ms, banner = _connect_plain(host, port)
        return smtp, ms, banner, port, None
    except (ConnectionRefusedError, TimeoutError, smtplib.SMTPServerDisconnected):
        pass
    except (OSError, smtplib.SMTPException) as exc:
        return None, 0.0, "", port, str(exc)

    for fp in fallback_ports:
        try:
            smtp, ms, banner = _connect_plain(host, fp)
            return smtp, ms, banner, fp, None
        except (OSError, smtplib.SMTPException):
            pass

    all_ports = ", ".join(str(p) for p in (port,) + fallback_ports)
    return None, 0.0, "", port, f"No port responded ({all_ports})"


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
    When *port* is ``25`` and the connection is refused or times out, the function
    automatically retries on ports 587 (RFC 6409) and 465 (RFC 8314) before
    reporting failure.

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

    # Connect — try port 25 first; fall back to 587 then 465 on refusal/timeout
    _fallback = _SMTP_FALLBACK_PORTS if port == 25 else ()
    _smtp, connect_ms, banner, actual_port, _conn_err = _connect_or_fallback(
        host, port, _fallback
    )
    if _smtp is None:
        result.checks.append(
            CheckResult(
                name="SMTP Connect",
                status=Status.ERROR,
                details=[f"Could not connect to {host} – {_conn_err}"],
            )
        )
        _tag(result.checks, proto_start, "Protocol")
        return result

    smtp = _smtp

    if actual_port != port:
        result.port = actual_port
        port = actual_port  # keep local var consistent for TLS/DANE calls below
        result.checks.append(
            CheckResult(
                name="SMTP Port Fallback",
                status=Status.INFO,
                value=str(actual_port),
                details=[f"Port 25 unreachable; fell back to port {actual_port}."],
            )
        )

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
            _check_pqc(host, port, result.checks)

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
