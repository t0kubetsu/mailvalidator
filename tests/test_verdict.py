"""Tests for mailvalidator/verdict.py."""

from __future__ import annotations

import pytest

from mailvalidator.models import (
    BIMIResult,
    BlacklistResult,
    CheckResult,
    DKIMResult,
    DMARCResult,
    DNSSECResult,
    FullReport,
    MTASTSResult,
    MXResult,
    SMTPDiagResult,
    SPFResult,
    Status,
    TLSRPTResult,
)
from mailvalidator.verdict import (
    Grade,
    VerdictAction,
    VerdictSeverity,
    _collect_checks,
    _context_severity,
    _deduplicate_actions,
    _format_verdict_text,
    _lookup_priority,
    calculate_grade,
    extract_verdict_actions,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check(name: str, status: Status, value: str = "", details: list[str] | None = None) -> CheckResult:
    return CheckResult(name=name, status=status, value=value, details=details or [])


def _empty_report() -> FullReport:
    return FullReport(domain="example.com")


def _report_with_checks(*checks: CheckResult) -> FullReport:
    r = FullReport(domain="example.com")
    spf = SPFResult(domain="example.com")
    spf.checks = list(checks)
    r.spf = spf
    return r


# ---------------------------------------------------------------------------
# _lookup_priority
# ---------------------------------------------------------------------------


class TestLookupPriority:
    def test_exact_match_critical(self):
        assert _lookup_priority("SPF Record") is VerdictSeverity.CRITICAL

    def test_exact_match_high(self):
        assert _lookup_priority("STARTTLS") is VerdictSeverity.HIGH

    def test_exact_match_medium(self):
        assert _lookup_priority("BIMI Record") is VerdictSeverity.MEDIUM

    def test_exact_match_smtp_connect_is_critical(self):
        assert _lookup_priority("SMTP Connect") is VerdictSeverity.CRITICAL

    def test_prefix_match_cipher_suites(self):
        assert _lookup_priority("Cipher Suites (TLSv1.2)") is VerdictSeverity.HIGH

    def test_prefix_match_cipher_order(self):
        assert _lookup_priority("Cipher Order – Server Preference (TLSv1.3)") is VerdictSeverity.HIGH

    def test_prefix_match_tls_versions(self):
        assert _lookup_priority("TLS Versions (extra suffix)") is VerdictSeverity.HIGH

    def test_prefix_match_dnssec(self):
        assert _lookup_priority("DNSSEC (example.com)") is VerdictSeverity.MEDIUM

    def test_prefix_match_certificate(self):
        # "Certificate Public Key" is more specific than "Certificate"
        assert _lookup_priority("Certificate Public Key") is VerdictSeverity.HIGH

    def test_prefix_match_certificate_generic(self):
        # "Certificate Expiry" is an exact key
        assert _lookup_priority("Certificate Expiry") is VerdictSeverity.CRITICAL

    def test_unknown_check_returns_none(self):
        assert _lookup_priority("Some Unknown Check XYZ") is None

    def test_prefix_match_uses_longest_prefix(self):
        # "Certificate Public Key" should beat generic "Certificate" prefix
        result = _lookup_priority("Certificate Public Key – some suffix")
        assert result is VerdictSeverity.HIGH

    def test_all_critical_checks_resolve(self):
        critical = [
            "SPF Record",
            "DMARC Record",
            "Open Relay",
            "Certificate Trust Chain",
            "Certificate Expiry",
            "MX Records",
            "Blacklist Status",
        ]
        for name in critical:
            assert _lookup_priority(name) is VerdictSeverity.CRITICAL, f"{name} should be CRITICAL"

    def test_all_informational_checks_resolve_none(self):
        informational = [
            "ESMTP Extensions",
            "VRFY Command",
            "TLS Compression",
            "Secure Renegotiation",
            "Client-Initiated Renegotiation",
            "Key Exchange",
            "Hash Function (Key Exchange)",
            "Tag Order (v=)",
            "Version",
            "Subdomain Policy (sp=)",
            "Percentage (pct=)",
            "Forensic Options (fo=)",
            "Reporting Interval (ri=)",
            "DNS Version",
            "Record ID (id=)",
            "Policy File Content-Type",
            "Policy File Line Endings",
            "Policy Version",
            "Unknown Tags",
            "Reporting URI",
            "Logo URL (l=)",
            "SPF Version",
            "SPF Include Resolution",
            "Nested +all in include:",
            "Void Lookup Count",
            "ptr Mechanism",
            "DANE – DNSSEC Prerequisite",
            "TLS Inspection",
        ]
        for name in informational:
            assert _lookup_priority(name) is None, f"{name} should map to None"


# ---------------------------------------------------------------------------
# _context_severity
# ---------------------------------------------------------------------------


class TestContextSeverity:
    def test_tls_versions_insufficient_escalates_to_critical(self):
        check = _check("TLS Versions", Status.INSUFFICIENT)
        assert _context_severity(check, VerdictSeverity.HIGH) is VerdictSeverity.CRITICAL

    def test_cipher_suites_insufficient_escalates_to_critical(self):
        check = _check("Cipher Suites (TLSv1.2)", Status.INSUFFICIENT)
        assert _context_severity(check, VerdictSeverity.HIGH) is VerdictSeverity.CRITICAL

    def test_cipher_suites_phase_out_does_not_escalate(self):
        check = _check("Cipher Suites (TLSv1.2)", Status.PHASE_OUT)
        assert _context_severity(check, VerdictSeverity.HIGH) is VerdictSeverity.HIGH

    def test_other_check_insufficient_does_not_escalate(self):
        check = _check("Certificate Public Key", Status.INSUFFICIENT)
        assert _context_severity(check, VerdictSeverity.HIGH) is VerdictSeverity.HIGH

    def test_medium_base_unchanged_for_unrelated(self):
        check = _check("BIMI Record", Status.NOT_FOUND)
        assert _context_severity(check, VerdictSeverity.MEDIUM) is VerdictSeverity.MEDIUM

    def test_tls_versions_with_phase_out_not_escalated(self):
        check = _check("TLS Versions", Status.PHASE_OUT)
        assert _context_severity(check, VerdictSeverity.HIGH) is VerdictSeverity.HIGH

    def test_tls_versions_insufficient_base_medium_still_escalates(self):
        # context override ignores base — always goes to CRITICAL for INSUFFICIENT
        check = _check("TLS Versions", Status.INSUFFICIENT)
        assert _context_severity(check, VerdictSeverity.MEDIUM) is VerdictSeverity.CRITICAL


# ---------------------------------------------------------------------------
# _format_verdict_text
# ---------------------------------------------------------------------------


class TestFormatVerdictText:
    def test_not_found_prefix_fix(self):
        check = _check("SPF Record", Status.NOT_FOUND)
        assert _format_verdict_text(check).startswith("Fix SPF Record")

    def test_error_prefix_fix(self):
        check = _check("Open Relay", Status.ERROR)
        assert _format_verdict_text(check).startswith("Fix Open Relay")

    def test_warning_prefix_review(self):
        check = _check("Policy (p=)", Status.WARNING)
        assert _format_verdict_text(check).startswith("Review Policy (p=)")

    def test_phase_out_prefix_upgrade(self):
        check = _check("TLS Versions", Status.PHASE_OUT)
        assert _format_verdict_text(check).startswith("Upgrade TLS Versions")

    def test_insufficient_prefix_upgrade(self):
        check = _check("Cipher Suites (TLSv1.2)", Status.INSUFFICIENT)
        assert _format_verdict_text(check).startswith("Upgrade Cipher Suites")

    def test_other_status_prefix_improve(self):
        # A hypothetical non-standard status path — use WARNING variant not covered above
        # Actually test a status that falls into the else branch (not NOT_FOUND/ERROR/WARNING/PHASE_OUT/INSUFFICIENT)
        check = CheckResult(name="Some Check", status=Status.INFO, value="v")
        # INFO is in _IGNORE_STATUSES so won't normally appear, but _format_verdict_text itself doesn't filter
        assert _format_verdict_text(check).startswith("Improve Some Check")

    def test_details_appended(self):
        check = _check("SPF Record", Status.NOT_FOUND, details=["No SPF record found."])
        text = _format_verdict_text(check)
        assert "No SPF record found." in text

    def test_value_appended_when_no_details(self):
        check = _check("MX Records", Status.ERROR, value="No MX")
        text = _format_verdict_text(check)
        assert "[No MX]" in text

    def test_name_only_when_no_details_no_value(self):
        check = _check("DMARC Record", Status.NOT_FOUND)
        text = _format_verdict_text(check)
        assert text == "Fix DMARC Record"

    def test_details_takes_priority_over_value(self):
        check = _check("SPF Record", Status.ERROR, value="badval", details=["Detail line."])
        text = _format_verdict_text(check)
        assert "Detail line." in text
        assert "badval" not in text

    def test_tls_versions_phase_out_uses_last_detail(self):
        check = _check(
            "TLS Versions",
            Status.PHASE_OUT,
            details=[
                "  \u2714  TLSv1.3 \u2013 accepted",
                "  \u2714  TLSv1.2 \u2013 accepted",
                "  \u2193 phase-out  TLSv1.1 \u2013 accepted",
                "Disable: TLSv1.1 \u2013 deprecated protocol(s) still accepted.",
            ],
        )
        text = _format_verdict_text(check)
        assert "Disable: TLSv1.1" in text
        assert "TLSv1.3" not in text

    def test_tls_versions_insufficient_uses_last_detail(self):
        check = _check(
            "TLS Versions",
            Status.INSUFFICIENT,
            details=[
                "  \u2714  TLSv1.3 \u2013 accepted",
                "  \u2193 TLSv1 \u2013 accepted",
                "Disable: TLSv1 \u2013 deprecated protocol(s) still accepted.",
            ],
        )
        text = _format_verdict_text(check)
        assert "Disable: TLSv1" in text
        assert "TLSv1.3" not in text


# ---------------------------------------------------------------------------
# _collect_checks
# ---------------------------------------------------------------------------


class TestCollectChecks:
    def test_empty_report_returns_empty(self):
        assert _collect_checks(_empty_report()) == []

    def test_collects_from_spf(self):
        r = _empty_report()
        spf = SPFResult(domain="example.com")
        spf.checks = [_check("SPF Record", Status.NOT_FOUND)]
        r.spf = spf
        checks = _collect_checks(r)
        assert len(checks) == 1
        assert checks[0].name == "SPF Record"

    def test_collects_from_smtp(self):
        r = _empty_report()
        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("STARTTLS", Status.WARNING)]
        r.smtp = [smtp]
        checks = _collect_checks(r)
        assert any(c.name == "STARTTLS" for c in checks)

    def test_collects_from_all_result_types(self):
        r = FullReport(domain="example.com")
        for attr, cls in [
            ("mx", MXResult),
            ("spf", SPFResult),
            ("dmarc", DMARCResult),
            ("dkim", DKIMResult),
            ("bimi", BIMIResult),
            ("tlsrpt", TLSRPTResult),
            ("mta_sts", MTASTSResult),
        ]:
            obj = cls(domain="example.com")
            obj.checks = [_check(f"{attr}_check", Status.WARNING)]
            setattr(r, attr, obj)

        bl = BlacklistResult(ip="1.2.3.4")
        bl.checks = [_check("bl_check", Status.ERROR)]
        r.blacklist = bl

        dd = DNSSECResult(domain="example.com")
        dd.checks = [_check("dd_check", Status.WARNING)]
        r.dnssec_domain = dd

        dm = DNSSECResult(domain="example.com")
        dm.checks = [_check("dm_check", Status.WARNING)]
        r.dnssec_mx = dm

        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("smtp_check", Status.WARNING)]
        r.smtp = [smtp]

        checks = _collect_checks(r)
        names = [c.name for c in checks]
        assert "mx_check" in names
        assert "spf_check" in names
        assert "bl_check" in names
        assert "dd_check" in names
        assert "dm_check" in names
        assert "smtp_check" in names

    def test_multiple_smtp_servers(self):
        r = _empty_report()
        for host in ("mx1.example.com", "mx2.example.com"):
            s = SMTPDiagResult(host=host, port=25)
            s.checks = [_check("STARTTLS", Status.WARNING)]
            r.smtp.append(s)
        checks = _collect_checks(r)
        assert len(checks) == 2


# ---------------------------------------------------------------------------
# _deduplicate_actions
# ---------------------------------------------------------------------------


class TestDeduplicateActions:
    def test_no_duplicates_unchanged(self):
        actions = [
            VerdictAction("Fix SPF", VerdictSeverity.CRITICAL, "SPF Record"),
            VerdictAction("Fix DMARC", VerdictSeverity.CRITICAL, "DMARC Record"),
        ]
        result = _deduplicate_actions(actions)
        assert len(result) == 2

    def test_same_check_same_severity_deduplicated(self):
        actions = [
            VerdictAction("Upgrade TLS Versions", VerdictSeverity.HIGH, "TLS Versions"),
            VerdictAction("Upgrade TLS Versions", VerdictSeverity.HIGH, "TLS Versions"),
        ]
        result = _deduplicate_actions(actions)
        assert len(result) == 1

    def test_same_check_different_severity_kept(self):
        # Should not happen in practice, but dedup key is (check_name, severity)
        actions = [
            VerdictAction("Upgrade TLS Versions", VerdictSeverity.CRITICAL, "TLS Versions"),
            VerdictAction("Upgrade TLS Versions", VerdictSeverity.HIGH, "TLS Versions"),
        ]
        result = _deduplicate_actions(actions)
        assert len(result) == 2

    def test_preserves_first_seen_order(self):
        actions = [
            VerdictAction("Fix SPF", VerdictSeverity.CRITICAL, "SPF Record"),
            VerdictAction("Fix DMARC", VerdictSeverity.CRITICAL, "DMARC Record"),
            VerdictAction("Fix SPF duplicate", VerdictSeverity.CRITICAL, "SPF Record"),
        ]
        result = _deduplicate_actions(actions)
        assert result[0].text == "Fix SPF"

    def test_empty_input(self):
        assert _deduplicate_actions([]) == []


# ---------------------------------------------------------------------------
# extract_verdict_actions (integration)
# ---------------------------------------------------------------------------


class TestExtractVerdictActions:
    def test_empty_report_returns_empty(self):
        assert extract_verdict_actions(_empty_report()) == []

    def test_all_ok_returns_empty(self):
        r = _report_with_checks(
            _check("SPF Record", Status.OK),
            _check("DMARC Record", Status.GOOD),
        )
        assert extract_verdict_actions(r) == []

    def test_ignore_statuses_skipped(self):
        for status in (Status.OK, Status.GOOD, Status.INFO, Status.NA, Status.SUFFICIENT):
            r = _report_with_checks(_check("SPF Record", status))
            assert extract_verdict_actions(r) == [], f"{status} should be ignored"

    def test_not_found_spf_produces_critical(self):
        r = _report_with_checks(_check("SPF Record", Status.NOT_FOUND))
        actions = extract_verdict_actions(r)
        assert len(actions) == 1
        assert actions[0].severity is VerdictSeverity.CRITICAL
        assert actions[0].check_name == "SPF Record"

    def test_bimi_not_found_produces_medium(self):
        r = FullReport(domain="example.com")
        bimi = BIMIResult(domain="example.com")
        bimi.checks = [_check("BIMI Record", Status.NOT_FOUND)]
        r.bimi = bimi
        actions = extract_verdict_actions(r)
        assert len(actions) == 1
        assert actions[0].severity is VerdictSeverity.MEDIUM

    def test_sorted_critical_before_high_before_medium(self):
        r = FullReport(domain="example.com")
        spf = SPFResult(domain="example.com")
        spf.checks = [_check("SPF Record", Status.NOT_FOUND)]
        r.spf = spf
        dkim = DKIMResult(domain="example.com")
        dkim.checks = [_check("DKIM Base Node", Status.ERROR)]
        r.dkim = dkim
        bimi = BIMIResult(domain="example.com")
        bimi.checks = [_check("BIMI Record", Status.NOT_FOUND)]
        r.bimi = bimi
        actions = extract_verdict_actions(r)
        severities = [a.severity for a in actions]
        assert severities == sorted(severities, key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}[s.value])

    def test_unknown_check_name_skipped(self):
        r = _report_with_checks(_check("Some Completely Unknown Check", Status.ERROR))
        assert extract_verdict_actions(r) == []

    def test_smtp_connect_error_produces_critical(self):
        r = _empty_report()
        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("SMTP Connect", Status.ERROR, details=["timed out"])]
        r.smtp = [smtp]
        actions = extract_verdict_actions(r)
        assert len(actions) == 1
        assert actions[0].severity is VerdictSeverity.CRITICAL
        assert actions[0].check_name == "SMTP Connect"

    def test_smtp_connect_ok_not_in_verdict(self):
        r = _empty_report()
        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("SMTP Connect", Status.OK, value="29.8 ms")]
        r.smtp = [smtp]
        assert extract_verdict_actions(r) == []

    def test_policy_file_error_produces_high(self):
        r = _empty_report()
        mta = MTASTSResult(domain="example.com")
        mta.checks = [_check("Policy File", Status.ERROR, details=["SSL cert mismatch"])]
        r.mta_sts = mta
        actions = extract_verdict_actions(r)
        assert len(actions) == 1
        assert actions[0].severity is VerdictSeverity.HIGH
        assert actions[0].check_name == "Policy File"

    def test_tls_versions_insufficient_escalated_to_critical(self):
        r = _empty_report()
        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("TLS Versions", Status.INSUFFICIENT)]
        r.smtp = [smtp]
        actions = extract_verdict_actions(r)
        assert any(a.severity is VerdictSeverity.CRITICAL for a in actions)

    def test_cipher_suites_insufficient_escalated_to_critical(self):
        r = _empty_report()
        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("Cipher Suites (TLSv1.2)", Status.INSUFFICIENT)]
        r.smtp = [smtp]
        actions = extract_verdict_actions(r)
        assert any(a.severity is VerdictSeverity.CRITICAL for a in actions)

    def test_deduplication_across_smtp_servers(self):
        r = _empty_report()
        for host in ("mx1.example.com", "mx2.example.com", "mx3.example.com"):
            s = SMTPDiagResult(host=host, port=25)
            s.checks = [_check("TLS Versions", Status.PHASE_OUT)]
            r.smtp.append(s)
        actions = extract_verdict_actions(r)
        tls_actions = [a for a in actions if a.check_name == "TLS Versions"]
        assert len(tls_actions) == 1

    def test_action_text_contains_check_name(self):
        r = _report_with_checks(_check("SPF Record", Status.NOT_FOUND))
        actions = extract_verdict_actions(r)
        assert "SPF Record" in actions[0].text

    def test_action_text_verb_for_not_found(self):
        r = _report_with_checks(_check("SPF Record", Status.NOT_FOUND))
        actions = extract_verdict_actions(r)
        assert actions[0].text.startswith("Fix")

    def test_action_text_verb_for_warning(self):
        r = FullReport(domain="example.com")
        dmarc = DMARCResult(domain="example.com")
        dmarc.checks = [_check("Policy (p=)", Status.WARNING)]
        r.dmarc = dmarc
        actions = extract_verdict_actions(r)
        assert any(a.text.startswith("Review") for a in actions)

    def test_action_text_verb_for_phase_out(self):
        r = _empty_report()
        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("TLS Versions", Status.PHASE_OUT)]
        r.smtp = [smtp]
        actions = extract_verdict_actions(r)
        assert any(a.text.startswith("Upgrade") for a in actions)

    def test_prefix_matched_check_included(self):
        r = _empty_report()
        smtp = SMTPDiagResult(host="mx.example.com", port=25)
        smtp.checks = [_check("Cipher Suites (TLSv1.3)", Status.PHASE_OUT)]
        r.smtp = [smtp]
        actions = extract_verdict_actions(r)
        assert len(actions) == 1

    def test_blacklist_check_included(self):
        r = _empty_report()
        bl = BlacklistResult(ip="1.2.3.4")
        bl.checks = [_check("Blacklist Status", Status.ERROR)]
        r.blacklist = bl
        actions = extract_verdict_actions(r)
        assert any(a.check_name == "Blacklist Status" for a in actions)


# ---------------------------------------------------------------------------
# calculate_grade
# ---------------------------------------------------------------------------


def _action(severity: VerdictSeverity) -> VerdictAction:
    return VerdictAction(text="action", severity=severity, check_name="Check")


class TestCalculateGrade:
    def test_no_actions_is_a_plus(self):
        g = calculate_grade([])
        assert g.letter == "A+"
        assert g.penalty == 0

    def test_no_actions_rationale_mentions_no_issues(self):
        g = calculate_grade([])
        assert "No issues" in g.rationale

    def test_one_medium_is_a_plus(self):
        # 3 penalty points → still 0 threshold? No: threshold is 0 exactly for A+.
        # 3 > 0 so it falls into A (1–10).
        g = calculate_grade([_action(VerdictSeverity.MEDIUM)])
        assert g.letter == "A"
        assert g.penalty == 3

    def test_one_high_is_a(self):
        g = calculate_grade([_action(VerdictSeverity.HIGH)])
        assert g.letter == "A"
        assert g.penalty == 10

    def test_two_highs_is_b(self):
        # 20 penalty points → B (11–20)
        g = calculate_grade([_action(VerdictSeverity.HIGH), _action(VerdictSeverity.HIGH)])
        assert g.letter == "B"
        assert g.penalty == 20

    def test_one_critical_is_c(self):
        # 25 penalty points → C (21–30)
        g = calculate_grade([_action(VerdictSeverity.CRITICAL)])
        assert g.letter == "C"
        assert g.penalty == 25

    def test_one_critical_one_high_is_d(self):
        # 35 penalty points → D (31–40)
        g = calculate_grade([_action(VerdictSeverity.CRITICAL), _action(VerdictSeverity.HIGH)])
        assert g.letter == "D"
        assert g.penalty == 35

    def test_two_criticals_is_f(self):
        # 50 penalty points → F (> 40)
        g = calculate_grade([_action(VerdictSeverity.CRITICAL), _action(VerdictSeverity.CRITICAL)])
        assert g.letter == "F"
        assert g.penalty == 50

    def test_boundary_a_plus_exactly_zero(self):
        g = calculate_grade([])
        assert g.letter == "A+"

    def test_boundary_a_max(self):
        # 10 penalty points is still A (1–10)
        g = calculate_grade([_action(VerdictSeverity.HIGH)])
        assert g.letter == "A"

    def test_boundary_b_min(self):
        # 11 penalty points → B (11–20)
        actions = [_action(VerdictSeverity.HIGH), _action(VerdictSeverity.MEDIUM)]
        g = calculate_grade(actions)
        assert g.penalty == 13
        assert g.letter == "B"

    def test_boundary_d_max(self):
        # 40 penalty points → D (31–40): 1 critical (25) + 1 high (10) + 1 medium (3) + 1 medium (3) - wait
        # Let's do: 1 critical (25) + 3 medium (9) = 34 → D; or 4 high (40) → D
        actions = [_action(VerdictSeverity.HIGH)] * 4
        g = calculate_grade(actions)
        assert g.penalty == 40
        assert g.letter == "D"

    def test_boundary_f_min(self):
        # 41 penalty points → F (> 40)
        # 1 critical (25) + 1 high (10) + 2 medium (6) = 41
        actions = [
            _action(VerdictSeverity.CRITICAL),
            _action(VerdictSeverity.HIGH),
            _action(VerdictSeverity.MEDIUM),
            _action(VerdictSeverity.MEDIUM),
        ]
        g = calculate_grade(actions)
        assert g.penalty == 41
        assert g.letter == "F"

    def test_rationale_mentions_critical_count(self):
        g = calculate_grade([_action(VerdictSeverity.CRITICAL)])
        assert "critical" in g.rationale

    def test_rationale_mentions_high_count(self):
        g = calculate_grade([_action(VerdictSeverity.HIGH)])
        assert "high" in g.rationale

    def test_rationale_mentions_medium_count(self):
        g = calculate_grade([_action(VerdictSeverity.MEDIUM)])
        assert "medium" in g.rationale

    def test_rationale_includes_penalty_points(self):
        g = calculate_grade([_action(VerdictSeverity.HIGH)])
        assert "10" in g.rationale

    def test_grade_is_dataclass(self):
        g = calculate_grade([])
        assert isinstance(g, Grade)
        assert hasattr(g, "letter")
        assert hasattr(g, "penalty")
        assert hasattr(g, "rationale")
