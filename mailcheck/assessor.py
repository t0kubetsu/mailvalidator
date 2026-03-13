"""High-level assessment API – orchestrates all checks."""

from __future__ import annotations

import socket
from typing import Callable

from mailcheck.checks.blacklist import check_blacklist
from mailcheck.checks.bimi import check_bimi
from mailcheck.checks.dkim import check_dkim
from mailcheck.checks.dmarc import check_dmarc
from mailcheck.checks.mta_sts import check_mta_sts
from mailcheck.checks.mx import check_mx
from mailcheck.checks.smtp import check_smtp
from mailcheck.checks.spf import check_spf
from mailcheck.checks.tlsrpt import check_tlsrpt
from mailcheck.models import FullReport, MXRecord, SMTPDiagResult


def _resolve_mx_ips(records: list[MXRecord]) -> list[str]:
    """Collect unique IPv4 addresses from MX records."""
    ips: list[str] = []
    for rec in records:
        for ip in rec.ip_addresses:
            if ip not in ips and "." in ip:  # simple IPv4 filter
                ips.append(ip)
    return ips


def assess(
    domain: str,
    *,
    bimi_selector: str = "default",
    smtp_port: int = 25,
    run_blacklist: bool = True,
    run_smtp: bool = True,
    progress_cb: Callable[[str], None] | None = None,
) -> FullReport:
    """Run all mail server checks for *domain* and return a :class:`FullReport`.

    Parameters
    ----------
    domain:
        Target domain name.
    bimi_selector:
        BIMI selector to query (default ``"default"``).
    smtp_port:
        SMTP port to probe (default ``25``).
    run_blacklist:
        Whether to run the DNSBL blacklist check (can be slow, uses threads).
    run_smtp:
        Whether to run SMTP diagnostics (requires outbound TCP 25 or chosen port).
    progress_cb:
        Optional callable invoked with a status string before each check group.
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    report = FullReport(domain=domain)

    # --- MX ---
    _cb("Checking MX records…")
    report.mx = check_mx(domain)

    # --- SPF ---
    _cb("Checking SPF record…")
    report.spf = check_spf(domain)

    # --- DMARC ---
    _cb("Checking DMARC record…")
    report.dmarc = check_dmarc(domain)

    # --- DKIM ---
    _cb("Checking DKIM base node…")
    report.dkim = check_dkim(domain)

    # --- BIMI ---
    _cb(f"Checking BIMI record (selector: {bimi_selector})…")
    report.bimi = check_bimi(domain, selector=bimi_selector)

    # --- TLSRPT ---
    _cb("Checking TLSRPT record…")
    report.tlsrpt = check_tlsrpt(domain)

    # --- MTA-STS ---
    _cb("Checking MTA-STS…")
    report.mta_sts = check_mta_sts(domain)

    # --- SMTP diagnostics ---
    if run_smtp and report.mx and report.mx.records:
        smtp_results: list[SMTPDiagResult] = []
        for mx_rec in report.mx.records[:3]:  # limit to first 3 MX servers
            _cb(f"SMTP diagnostics on {mx_rec.exchange}:{smtp_port}…")
            smtp_results.append(check_smtp(mx_rec.exchange, port=smtp_port))
        report.smtp = smtp_results

    # --- Blacklist ---
    if run_blacklist:
        mx_ips = _resolve_mx_ips(report.mx.records) if report.mx else []
        if mx_ips:
            target_ip = mx_ips[0]
            _cb(f"Running blacklist check on {target_ip} (this may take ~30s)…")
            report.blacklist = check_blacklist(target_ip)
        else:
            # fall back to domain A record
            try:
                ip = socket.gethostbyname(domain)
                _cb(f"Running blacklist check on {ip}…")
                report.blacklist = check_blacklist(ip)
            except socket.gaierror:
                pass

    return report
