"""Verdict panel: extract and display prioritised security actions.

Analyses a :class:`~mailvalidator.models.FullReport` and produces a ranked
list of :class:`VerdictAction` items highlighting the most important
improvements an operator should make.  Severity is context-aware — e.g.
``BIMI Record`` missing is at most MEDIUM because BIMI is an optional
enhancement, whereas ``SPF Record`` missing is CRITICAL because it directly
affects deliverability.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from mailvalidator.models import CheckResult, FullReport, Status


class VerdictSeverity(str, Enum):
    """Severity level for a verdict action item.

    Ordered from most to least urgent:
    ``CRITICAL`` → ``HIGH`` → ``MEDIUM``.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@dataclass
class VerdictAction:
    """A single prioritised action derived from a check result.

    :param text: Human-readable action description shown in the verdict panel.
    :param severity: Importance level of this action.
    :param check_name: Name of the originating :class:`~mailvalidator.models.CheckResult`.
    """

    text: str
    severity: VerdictSeverity
    check_name: str


# Statuses that indicate a check passed — never generate a verdict action.
_IGNORE_STATUSES: frozenset[Status] = frozenset(
    {Status.OK, Status.GOOD, Status.INFO, Status.NA, Status.SUFFICIENT}
)

# Maps check name prefixes to their default verdict severity.
# ``None`` → explicitly informational; never appears in the verdict panel.
# Prefix matching is used: ``"Cipher Suites"`` matches
# ``"Cipher Suites (TLSv1.2)"``.  Longer prefixes take precedence.
_PRIORITY: dict[str, VerdictSeverity | None] = {
    # ------------------------------------------------------------------ CRITICAL
    # Missing or broken items that directly affect email deliverability.
    "SPF Record": VerdictSeverity.CRITICAL,
    "DMARC Record": VerdictSeverity.CRITICAL,
    "Open Relay": VerdictSeverity.CRITICAL,
    "Certificate Trust Chain": VerdictSeverity.CRITICAL,
    "Certificate Expiry": VerdictSeverity.CRITICAL,
    "MX Records": VerdictSeverity.CRITICAL,
    "Blacklist Status": VerdictSeverity.CRITICAL,
    # ------------------------------------------------------------------ HIGH
    # Important security gaps that should be addressed soon.
    "DKIM Base Node": VerdictSeverity.HIGH,
    "STARTTLS": VerdictSeverity.HIGH,
    "Reverse DNS (PTR)": VerdictSeverity.HIGH,
    "MTA-STS DNS Record": VerdictSeverity.HIGH,
    "TLSRPT Record": VerdictSeverity.HIGH,
    # Certificate checks (more-specific keys above win over "Certificate" catch-all)
    "Certificate Public Key": VerdictSeverity.HIGH,
    "Certificate Domain Match": VerdictSeverity.HIGH,
    "Certificate Signature": VerdictSeverity.HIGH,
    "Certificate": VerdictSeverity.HIGH,
    # MTA-STS policy enforcement
    "Policy Mode": VerdictSeverity.HIGH,
    # DMARC policy — p=none is a WARNING → HIGH; invalid policy is ERROR → CRITICAL
    "Policy (p=)": VerdictSeverity.HIGH,
    # TLS/cipher checks; INSUFFICIENT status → escalated to CRITICAL at runtime
    "Cipher Suites": VerdictSeverity.HIGH,
    "Cipher Order": VerdictSeverity.HIGH,
    "TLS Versions": VerdictSeverity.HIGH,
    # Misconfigured SMTP protocol presentation
    "Banner FQDN": VerdictSeverity.HIGH,
    "EHLO Domain": VerdictSeverity.HIGH,
    # SPF policy / lookup issues
    "SPF Policy": VerdictSeverity.HIGH,
    "DNS Lookup Count": VerdictSeverity.HIGH,
    "Multiple SPF Records": VerdictSeverity.HIGH,
    # DANE certificate mismatch is actionable when DANE is deployed
    "DANE – Certificate Match": VerdictSeverity.HIGH,
    # ------------------------------------------------------------------ MEDIUM
    # Optional enhancements — good to have but not urgent.
    "BIMI Record": VerdictSeverity.MEDIUM,
    "CAA Records": VerdictSeverity.MEDIUM,
    "DANE – TLSA Existence": VerdictSeverity.MEDIUM,
    "DANE – Matching Type": VerdictSeverity.MEDIUM,
    "DANE – Rollover Scheme": VerdictSeverity.MEDIUM,
    "DNSSEC": VerdictSeverity.MEDIUM,
    "Duplicate Priorities": VerdictSeverity.MEDIUM,
    # ------------------------------------------------------------------ IGNORE
    # Informational checks — outcome is always noted, never actionable.
    "SMTP Connect": None,
    "ESMTP Extensions": None,
    "VRFY Command": None,
    "TLS Compression": None,
    "Secure Renegotiation": None,
    "Client-Initiated Renegotiation": None,
    "Key Exchange": None,
    "Hash Function (Key Exchange)": None,
    "Tag Order (v=)": None,
    "Version": None,
    "Subdomain Policy (sp=)": None,
    "Percentage (pct=)": None,
    "Forensic Options (fo=)": None,
    "Reporting Interval (ri=)": None,
    "DNS Version": None,
    "Record ID (id=)": None,
    "Policy File Content-Type": None,
    "Policy File Line Endings": None,
    "Policy Version": None,
    "Unknown Tags": None,
    "Reporting URI": None,
    "Logo URL (l=)": None,
    "SPF Version": None,
    "SPF Include Resolution": None,
    "Nested +all in include:": None,
    "Void Lookup Count": None,
    "ptr Mechanism": None,
    "DANE – DNSSEC Prerequisite": None,
    "TLS Inspection": None,
}

_SEVERITY_ORDER: dict[VerdictSeverity, int] = {
    VerdictSeverity.CRITICAL: 0,
    VerdictSeverity.HIGH: 1,
    VerdictSeverity.MEDIUM: 2,
}


def _lookup_priority(check_name: str) -> VerdictSeverity | None:
    """Return the verdict severity for *check_name*, or ``None`` to skip it.

    Resolution order:

    1. Exact key match in :data:`_PRIORITY`.
    2. Longest prefix match (e.g. ``"Cipher Suites"`` matches
       ``"Cipher Suites (TLSv1.2)"``).
    3. ``None`` — unknown check; silently skipped.

    :param check_name: Name of a :class:`~mailvalidator.models.CheckResult`.
    :type check_name: str
    :returns: Severity or ``None``.
    :rtype: VerdictSeverity or None
    """
    if check_name in _PRIORITY:
        return _PRIORITY[check_name]

    best_len = -1
    best_val: VerdictSeverity | None = None
    found = False
    for key, val in _PRIORITY.items():
        if check_name.startswith(key) and len(key) > best_len:
            best_len = len(key)
            best_val = val
            found = True
    return best_val if found else None


def _context_severity(check: CheckResult, base: VerdictSeverity) -> VerdictSeverity:
    """Apply context-aware severity overrides for *check*.

    Rules applied (in order):

    * ``TLS Versions`` or ``Cipher Suites`` with status ``INSUFFICIENT``
      → escalate to ``CRITICAL`` regardless of *base*.

    :param check: The check result being evaluated.
    :type check: ~mailvalidator.models.CheckResult
    :param base: Default severity from :data:`_PRIORITY`.
    :type base: VerdictSeverity
    :returns: Adjusted severity.
    :rtype: VerdictSeverity
    """
    if check.status == Status.INSUFFICIENT and (
        check.name.startswith("TLS Versions") or check.name.startswith("Cipher Suites")
    ):
        return VerdictSeverity.CRITICAL
    return base


def _format_verdict_text(check: CheckResult) -> str:
    """Return a human-readable action string for *check*.

    The verb prefix reflects the nature of the issue:

    * ``Fix`` — missing or broken (``NOT_FOUND`` / ``ERROR``)
    * ``Review`` — suboptimal policy (``WARNING``)
    * ``Upgrade`` — deprecated or below-minimum quality (``PHASE_OUT`` / ``INSUFFICIENT``)
    * ``Improve`` — any other actionable status

    The first detail line is appended when available for additional context.

    :param check: Source check result.
    :type check: ~mailvalidator.models.CheckResult
    :returns: Action text suitable for the verdict table.
    :rtype: str
    """
    if check.status in (Status.NOT_FOUND, Status.ERROR):
        prefix = "Fix"
    elif check.status == Status.WARNING:
        prefix = "Review"
    elif check.status in (Status.PHASE_OUT, Status.INSUFFICIENT):
        prefix = "Upgrade"
    else:
        prefix = "Improve"

    if check.details:
        return f"{prefix} {check.name}: {check.details[0]}"
    if check.value:
        return f"{prefix} {check.name} [{check.value}]"
    return f"{prefix} {check.name}"


def _collect_checks(report: FullReport) -> list[CheckResult]:
    """Collect all :class:`~mailvalidator.models.CheckResult` items from *report*.

    :param report: Full assessment report.
    :type report: ~mailvalidator.models.FullReport
    :returns: Flat list of every check result present in the report.
    :rtype: list[~mailvalidator.models.CheckResult]
    """
    collected: list[CheckResult] = []
    for result_obj in (
        report.mx,
        report.spf,
        report.dmarc,
        report.dkim,
        report.bimi,
        report.tlsrpt,
        report.mta_sts,
        report.blacklist,
        report.dnssec_domain,
        report.dnssec_mx,
    ):
        if result_obj is not None:
            collected.extend(result_obj.checks)
    for smtp_result in report.smtp:
        collected.extend(smtp_result.checks)
    return collected


def _deduplicate_actions(actions: list[VerdictAction]) -> list[VerdictAction]:
    """Remove duplicate actions with the same ``(check_name, severity)`` pair.

    Deduplication is important for multi-server SMTP results where the same
    logical check (e.g. ``TLS Versions``) is run once per MX server.

    :param actions: Raw list of actions (may contain duplicates).
    :type actions: list[VerdictAction]
    :returns: List with duplicates removed, preserving first-seen order.
    :rtype: list[VerdictAction]
    """
    seen: set[tuple[str, str]] = set()
    result: list[VerdictAction] = []
    for action in actions:
        key = (action.check_name, action.severity.value)
        if key not in seen:
            seen.add(key)
            result.append(action)
    return result


def extract_verdict_actions(report: FullReport) -> list[VerdictAction]:
    """Extract prioritised action items from *report*.

    Checks that already pass (status ``OK``, ``GOOD``, ``INFO``, ``N/A``, or
    ``SUFFICIENT``) are silently skipped.  For every non-passing check the
    severity is looked up via :func:`_lookup_priority` and an optional
    context override is applied by :func:`_context_severity`.

    Checks whose name maps to ``None`` in :data:`_PRIORITY` (explicitly
    informational) are also skipped.  Unknown check names are skipped too.

    Duplicate ``(check_name, severity)`` pairs are collapsed via
    :func:`_deduplicate_actions` to avoid noisy repetition across MX servers.
    The result is sorted from most to least urgent.

    :param report: Full assessment report.
    :type report: ~mailvalidator.models.FullReport
    :returns: Deduplicated, severity-sorted list of action items.  Empty list
        if everything passes.
    :rtype: list[VerdictAction]
    """
    actions: list[VerdictAction] = []

    for check in _collect_checks(report):
        if check.status in _IGNORE_STATUSES:
            continue

        base_sev = _lookup_priority(check.name)
        if base_sev is None:
            continue

        sev = _context_severity(check, base_sev)
        text = _format_verdict_text(check)
        actions.append(VerdictAction(text=text, severity=sev, check_name=check.name))

    actions = _deduplicate_actions(actions)
    actions.sort(key=lambda a: _SEVERITY_ORDER[a.severity])
    return actions
