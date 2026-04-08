"""Tests for mailvalidator/reporter.py."""

from __future__ import annotations

from unittest.mock import patch

import pytest

import mailvalidator.reporter as _reporter_module
from mailvalidator.models import (
    BIMIResult,
    BlacklistResult,
    CheckResult,
    DKIMResult,
    DMARCResult,
    DNSSECResult,
    FullReport,
    MTASTSResult,
    MXRecord,
    MXResult,
    SMTPDiagResult,
    SPFResult,
    Status,
    TLSRPTResult,
)
from mailvalidator.reporter import (
    _checks_table,
    _status_text,
    print_bimi,
    print_blacklist,
    print_dkim,
    print_dmarc,
    print_dnssec_domain,
    print_dnssec_mx,
    print_full_report,
    print_mta_sts,
    print_mx,
    print_smtp,
    print_spf,
    print_tlsrpt,
    print_verdict,
    save_report,
)
from mailvalidator.verdict import VerdictAction, VerdictSeverity
from tests.conftest import console_capture


def _patch_console(con):
    return patch.object(_reporter_module, "console", con)


class TestStatusText:
    def test_ok_contains_ok(self):
        assert "OK" in _status_text(Status.OK).plain

    def test_error_contains_error(self):
        assert "ERROR" in _status_text(Status.ERROR).plain

    def test_all_statuses_have_style(self):
        for st in Status:
            assert _status_text(st).plain


class TestChecksTable:
    def _check(self, **kw):
        return CheckResult(
            name=kw.get("name", "T"),
            status=kw.get("status", Status.OK),
            value=kw.get("value", ""),
            details=kw.get("details", []),
        )

    def test_returns_rich_table(self):
        from rich.table import Table

        assert isinstance(_checks_table([self._check()]), Table)

    def test_empty_input(self):
        from rich.table import Table

        assert isinstance(_checks_table([]), Table)

    def test_details_rendered(self):
        con, buf = console_capture()
        con.print(_checks_table([self._check(details=["line1", "line2"])]))
        assert "line1" in buf.getvalue()

    def test_value_rendered(self):
        con, buf = console_capture()
        con.print(_checks_table([self._check(value="myvalue")]))
        assert "myvalue" in buf.getvalue()


class TestPrintMx:
    def _result(self, with_ns=False):
        r = MXResult(domain="example.com")
        r.checks = [CheckResult(name="MX Records", status=Status.OK, value="1")]
        r.records = [
            MXRecord(priority=10, exchange="mail.example.com", ip_addresses=["1.2.3.4"])
        ]
        if with_ns:
            r.authoritative_ns = ["ns1.example.com"]
        return r

    def test_prints_domain(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_mx(self._result())
        assert "example.com" in buf.getvalue()

    def test_prints_ns_when_present(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_mx(self._result(with_ns=True))
        assert "ns1.example.com" in buf.getvalue()


class TestPrintSmtp:
    def test_prints_host_and_port(self):
        r = SMTPDiagResult(host="mail.example.com", port=25)
        r.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_smtp([r])
        assert "mail.example.com" in buf.getvalue()

    def test_multiple_servers(self):
        r1 = SMTPDiagResult(host="mx1.example.com", port=25)
        r1.checks = []
        r2 = SMTPDiagResult(host="mx2.example.com", port=25)
        r2.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_smtp([r1, r2])
        assert "mx1.example.com" in buf.getvalue()
        assert "mx2.example.com" in buf.getvalue()

    def test_sectioned_checks_render_panels(self):
        r = SMTPDiagResult(host="mail.example.com", port=25)
        r.checks = [
            CheckResult(name="Connect", status=Status.OK, section="Protocol"),
            CheckResult(name="TLS Version", status=Status.OK, section="TLS"),
        ]
        con, buf = console_capture()
        with _patch_console(con):
            print_smtp([r])
        output = buf.getvalue()
        assert "Protocol" in output
        assert "TLS" in output
        assert "Connect" in output

    def test_unsectioned_checks_render_flat_table(self):
        r = SMTPDiagResult(host="mail.example.com", port=25)
        r.checks = [CheckResult(name="SomeCheck", status=Status.OK)]
        con, buf = console_capture()
        with _patch_console(con):
            print_smtp([r])
        assert "SomeCheck" in buf.getvalue()

    def test_mixed_sectioned_and_unsectioned(self):
        r = SMTPDiagResult(host="mail.example.com", port=25)
        r.checks = [
            CheckResult(name="ProtoCheck", status=Status.OK, section="Protocol"),
            CheckResult(name="Bare", status=Status.OK),
        ]
        con, buf = console_capture()
        with _patch_console(con):
            print_smtp([r])
        output = buf.getvalue()
        assert "Protocol" in output
        assert "Bare" in output

    def test_unknown_section_name_rendered(self):
        r = SMTPDiagResult(host="mail.example.com", port=25)
        r.checks = [
            CheckResult(name="WeirdCheck", status=Status.OK, section="Custom"),
        ]
        con, buf = console_capture()
        with _patch_console(con):
            print_smtp([r])
        output = buf.getvalue()
        assert "Custom" in output
        assert "WeirdCheck" in output


class TestPrintSpf:
    def test_prints_domain(self):
        r = SPFResult(domain="example.com")
        r.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_spf(r)
        assert "example.com" in buf.getvalue()


class TestPrintDmarc:
    def test_prints_domain(self):
        r = DMARCResult(domain="example.com")
        r.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_dmarc(r)
        assert "example.com" in buf.getvalue()


class TestPrintDkim:
    def test_prints_domain(self):
        r = DKIMResult(domain="example.com")
        r.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_dkim(r)
        assert "example.com" in buf.getvalue()


class TestPrintBimi:
    def test_prints_domain(self):
        r = BIMIResult(domain="example.com")
        r.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_bimi(r)
        assert "example.com" in buf.getvalue()


class TestPrintTlsrpt:
    def test_prints_domain(self):
        r = TLSRPTResult(domain="example.com")
        r.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_tlsrpt(r)
        assert "example.com" in buf.getvalue()


class TestPrintMtaSts:
    def test_prints_domain(self):
        r = MTASTSResult(domain="example.com")
        r.checks = []
        con, buf = console_capture()
        with _patch_console(con):
            print_mta_sts(r)
        assert "example.com" in buf.getvalue()


class TestPrintBlacklist:
    def test_clean_ip(self):
        r = BlacklistResult(ip="1.2.3.4")
        r.total_checked = 10
        r.listed_on = []
        r.checks = [CheckResult(name="Blacklist", status=Status.OK)]
        con, buf = console_capture()
        with _patch_console(con):
            print_blacklist(r)
        assert "1.2.3.4" in buf.getvalue()
        assert "10" in buf.getvalue()

    def test_listed_ip(self):
        r = BlacklistResult(ip="5.6.7.8")
        r.total_checked = 10
        r.listed_on = ["zen.spamhaus.org"]
        r.checks = [CheckResult(name="Blacklist", status=Status.ERROR)]
        con, buf = console_capture()
        with _patch_console(con):
            print_blacklist(r)
        assert "5.6.7.8" in buf.getvalue()


class TestPrintDnssecDomain:
    def test_prints_domain(self):
        r = DNSSECResult(domain="example.com")
        r.checks = [
            CheckResult(
                name="DNSSEC (example.com)", status=Status.OK, value="signed — secure"
            )
        ]
        con, buf = console_capture()
        with _patch_console(con):
            print_dnssec_domain(r)
        assert "example.com" in buf.getvalue()

    def test_prints_check_value(self):
        r = DNSSECResult(domain="example.com")
        r.checks = [
            CheckResult(
                name="DNSSEC (example.com)", status=Status.NOT_FOUND, value="unsigned"
            )
        ]
        con, buf = console_capture()
        with _patch_console(con):
            print_dnssec_domain(r)
        assert "unsigned" in buf.getvalue()


class TestPrintDnssecMx:
    def test_prints_domain(self):
        r = DNSSECResult(domain="example.com")
        r.checks = [
            CheckResult(
                name="DNSSEC (mx1.example.com)",
                status=Status.OK,
                value="signed — secure",
            )
        ]
        con, buf = console_capture()
        with _patch_console(con):
            print_dnssec_mx(r)
        assert "example.com" in buf.getvalue()

    def test_prints_check_for_each_mx(self):
        r = DNSSECResult(domain="example.com")
        r.checks = [
            CheckResult(
                name="DNSSEC (mx1.example.com)",
                status=Status.OK,
                value="signed — secure",
            ),
            CheckResult(
                name="DNSSEC (mx2.example.com)", status=Status.ERROR, value="bogus"
            ),
        ]
        con, buf = console_capture()
        with _patch_console(con):
            print_dnssec_mx(r)
        out = buf.getvalue()
        assert "mx1.example.com" in out
        assert "mx2.example.com" in out


class TestPrintFullReport:
    def _report(self, smtp=False, blacklist=False, dnssec=False):
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
            obj.checks = []
            if attr == "mx":
                obj.records = []
            setattr(r, attr, obj)
        if smtp:
            s = SMTPDiagResult(host="mail.example.com", port=25)
            s.checks = []
            r.smtp = [s]
        if blacklist:
            b = BlacklistResult(ip="1.2.3.4")
            b.total_checked = 5
            b.listed_on = []
            b.checks = []
            r.blacklist = b
        if dnssec:
            r.dnssec_domain = DNSSECResult(domain="example.com")
            r.dnssec_domain.checks = [
                CheckResult(
                    name="DNSSEC (example.com)",
                    status=Status.OK,
                    value="signed — secure",
                )
            ]
            r.dnssec_mx = DNSSECResult(domain="example.com")
            r.dnssec_mx.checks = [
                CheckResult(
                    name="DNSSEC (mx1.example.com)",
                    status=Status.OK,
                    value="signed — secure",
                )
            ]
        return r

    def test_domain_in_output(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(self._report())
        assert "example.com" in buf.getvalue()

    def test_with_smtp_and_blacklist(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(self._report(smtp=True, blacklist=True))
        assert "mail.example.com" in buf.getvalue()
        assert "1.2.3.4" in buf.getvalue()

    def test_with_dnssec_sections(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(self._report(dnssec=True))
        assert "DNSSEC" in buf.getvalue()

    def test_empty_report_no_crash(self):
        r = FullReport(domain="empty.example.com")
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(r)
        assert "empty.example.com" in buf.getvalue()


class TestPrintVerdict:
    """Tests for :func:`~mailvalidator.reporter.print_verdict`."""

    def _action(self, severity: VerdictSeverity, check_name: str = "SPF Record", text: str | None = None) -> VerdictAction:
        if text is None:
            text = f"Fix {check_name}"
        return VerdictAction(text=text, severity=severity, check_name=check_name)

    def test_renders_critical_label(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_verdict([self._action(VerdictSeverity.CRITICAL)])
        assert "CRITICAL" in buf.getvalue()

    def test_renders_high_label(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_verdict([self._action(VerdictSeverity.HIGH, "STARTTLS")])
        assert "HIGH" in buf.getvalue()

    def test_renders_medium_label(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_verdict([self._action(VerdictSeverity.MEDIUM, "BIMI Record")])
        assert "MEDIUM" in buf.getvalue()

    def test_renders_action_text(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_verdict([self._action(VerdictSeverity.CRITICAL, text="Fix SPF Record: no record found")])
        assert "Fix SPF Record" in buf.getvalue()

    def test_renders_panel_title(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_verdict([self._action(VerdictSeverity.HIGH, "STARTTLS")])
        assert "Security Verdict" in buf.getvalue()

    def test_renders_multiple_actions(self):
        con, buf = console_capture()
        with _patch_console(con):
            print_verdict([
                self._action(VerdictSeverity.CRITICAL, "SPF Record"),
                self._action(VerdictSeverity.HIGH, "STARTTLS"),
                self._action(VerdictSeverity.MEDIUM, "BIMI Record"),
            ])
        output = buf.getvalue()
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output

    def test_verdict_shown_in_full_report_when_actions_exist(self):
        r = FullReport(domain="example.com")
        spf = SPFResult(domain="example.com")
        spf.checks = [CheckResult(name="SPF Record", status=Status.NOT_FOUND)]
        r.spf = spf
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(r)
        assert "Security Verdict" in buf.getvalue()

    def test_verdict_not_shown_in_full_report_when_all_pass(self):
        r = FullReport(domain="example.com")
        spf = SPFResult(domain="example.com")
        spf.checks = [CheckResult(name="SPF Record", status=Status.OK, value="v=spf1 -all")]
        r.spf = spf
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(r)
        assert "Security Verdict" not in buf.getvalue()


class TestSaveReport:
    """Tests for :func:`~mailvalidator.reporter.save_report`."""

    def _printed_report(self):
        """Prime the console buffer with a minimal full report."""
        r = FullReport(domain="example.com")
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(r)

    def test_save_text_calls_save_text(self, tmp_path):
        dest = str(tmp_path / "report.txt")
        with patch.object(_reporter_module, "console") as mock_con:
            save_report(dest)
        mock_con.save_text.assert_called_once_with(dest, clear=False)

    def test_save_svg_calls_save_svg(self, tmp_path):
        dest = str(tmp_path / "report.svg")
        with patch.object(_reporter_module, "console") as mock_con:
            save_report(dest)
        mock_con.save_svg.assert_called_once_with(dest, clear=False)

    def test_save_html_calls_save_html(self, tmp_path):
        dest = str(tmp_path / "report.html")
        with patch.object(_reporter_module, "console") as mock_con:
            save_report(dest)
        mock_con.save_html.assert_called_once_with(dest, clear=False)

    def test_unknown_extension_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError, match="Unsupported export format"):
            save_report(str(tmp_path / "report.pdf"))

    def test_no_extension_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError, match="Unsupported export format"):
            save_report(str(tmp_path / "report"))

    def test_extension_is_case_insensitive(self, tmp_path):
        dest = str(tmp_path / "report.TXT")
        with patch.object(_reporter_module, "console") as mock_con:
            save_report(dest)
        mock_con.save_text.assert_called_once()

    def test_console_has_record_enabled(self):
        """The module-level console must be created with record=True."""
        assert _reporter_module.console._record_buffer is not None
