"""High-level assessment API – orchestrates all per-domain checks.

Typical usage::

    from mailvalidator.assessor import assess

    report = assess("example.com", progress_cb=print)
"""

from __future__ import annotations

import socket
from typing import Callable

from mailvalidator.checks.blacklist import check_blacklist
from mailvalidator.checks.bimi import check_bimi
from mailvalidator.checks.dkim import check_dkim
from mailvalidator.checks.dmarc import check_dmarc
from mailvalidator.checks.mta_sts import check_mta_sts
from mailvalidator.checks.mx import check_mx
from mailvalidator.checks.smtp import check_smtp
from mailvalidator.checks.spf import check_spf
from mailvalidator.checks.tlsrpt import check_tlsrpt
from mailvalidator.models import FullReport, MXRecord, SMTPDiagResult


def _resolve_mx_ips(records: list[MXRecord]) -> list[str]:
    """Return unique IPv4 addresses collected from a list of MX records.

    :param records: MX records to extract IP addresses from.
    :returns: Deduplicated list of IPv4 address strings.
    :rtype: list[str]
    """
    ips: list[str] = []
    for rec in records:
        for ip in rec.ip_addresses:
            if ip not in ips and "." in ip:  # simple IPv4 filter
                ips.append(ip)
    return ips


def assess(
    domain: str,
    *,
    smtp_port: int = 25,
    run_blacklist: bool = True,
    run_smtp: bool = True,
    progress_cb: Callable[[str], None] | None = None,
) -> FullReport:
    """Run all mail server checks for *domain* and return a :class:`~mailvalidator.models.FullReport`.

    :param domain: The target domain name to assess (e.g. ``"example.com"``).
    :param smtp_port: TCP port used for SMTP diagnostics.  Defaults to ``25``.
    :param run_blacklist: When ``True`` (default), check the first MX IP
        against 100+ DNSBLs.  This step is parallelised but can take up to
        ~30 s on slow networks.
    :param run_smtp: When ``True`` (default), probe each MX server via SMTP
        and STARTTLS.  Requires outbound TCP access to *smtp_port*.
    :param progress_cb: Optional callable invoked with a short status string
        before each check group.  Useful for driving a progress spinner in
        the CLI.
    :returns: Populated :class:`~mailvalidator.models.FullReport`; individual
        fields are ``None`` when the corresponding check was skipped.
    :rtype: ~mailvalidator.models.FullReport
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    report = FullReport(domain=domain)

    _cb("Checking MX records…")
    report.mx = check_mx(domain)

    _cb("Checking SPF record…")
    report.spf = check_spf(domain)

    _cb("Checking DMARC record…")
    report.dmarc = check_dmarc(domain)

    _cb("Checking DKIM base node…")
    report.dkim = check_dkim(domain)

    _cb("Checking BIMI record…")
    report.bimi = check_bimi(domain)

    _cb("Checking TLSRPT record…")
    report.tlsrpt = check_tlsrpt(domain)

    _cb("Checking MTA-STS…")
    report.mta_sts = check_mta_sts(domain)

    if run_smtp and report.mx and report.mx.records:
        smtp_results: list[SMTPDiagResult] = []
        for mx_rec in report.mx.records[:3]:  # probe at most the first 3 MX servers
            _cb(f"SMTP diagnostics on {mx_rec.exchange}:{smtp_port}…")
            smtp_results.append(check_smtp(mx_rec.exchange, port=smtp_port))
        report.smtp = smtp_results

    if run_blacklist:
        mx_ips = _resolve_mx_ips(report.mx.records) if report.mx else []
        if mx_ips:
            target_ip = mx_ips[0]
            _cb(f"Blacklist check on {target_ip} (may take ~30 s)…")
            report.blacklist = check_blacklist(target_ip)
        else:
            # Fall back to the domain's A record when no MX IPs are available.
            try:
                ip = socket.gethostbyname(domain)
                _cb(f"Blacklist check on {ip}…")
                report.blacklist = check_blacklist(ip)
            except socket.gaierror:
                pass

    return report
