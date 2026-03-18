"""Tests for mailvalidator/reporter.py."""

from __future__ import annotations

from unittest.mock import patch


import mailvalidator.reporter as _reporter_module
from mailvalidator.models import (
    BIMIResult,
    BlacklistResult,
    CheckResult,
    DMARCResult,
    DKIMResult,
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
    print_full_report,
    print_mta_sts,
    print_mx,
    print_smtp,
    print_spf,
    print_tlsrpt,
)
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


class TestPrintFullReport:
    def _report(self, smtp=False, blacklist=False):
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

    def test_empty_report_no_crash(self):
        r = FullReport(domain="empty.example.com")
        con, buf = console_capture()
        with _patch_console(con):
            print_full_report(r)
        assert "empty.example.com" in buf.getvalue()
