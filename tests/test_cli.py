"""Tests for mailvalidator/cli.py."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from mailvalidator.cli import _validate_domain, _validate_host, _validate_ip, app
from mailvalidator.models import (
    BIMIResult,
    BlacklistResult,
    DKIMResult,
    DMARCResult,
    FullReport,
    MTASTSResult,
    SMTPDiagResult,
    SPFResult,
    TLSRPTResult,
)
from tests.conftest import make_mx_result, make_simple_result

_runner = CliRunner()


class TestValidateDomain:
    def test_valid_domain(self):
        assert _validate_domain("example.com") == "example.com"

    def test_valid_subdomain(self):
        assert _validate_domain("mail.example.co.uk") == "mail.example.co.uk"

    def test_valid_trailing_dot(self):
        assert _validate_domain("example.com.") == "example.com."

    def test_single_label_rejected(self):
        with pytest.raises(typer.BadParameter):
            _validate_domain("localhost")

    def test_empty_string_rejected(self):
        with pytest.raises(typer.BadParameter):
            _validate_domain("")

    def test_invalid_chars_rejected(self):
        with pytest.raises(typer.BadParameter):
            _validate_domain("exa mple.com")


class TestValidateHost:
    def test_valid_fqdn(self):
        assert _validate_host("mail.example.com") == "mail.example.com"

    def test_valid_ipv4(self):
        assert _validate_host("1.2.3.4") == "1.2.3.4"

    def test_valid_ipv6(self):
        assert _validate_host("2001:db8::1") == "2001:db8::1"

    def test_single_label_allowed(self):
        assert _validate_host("mailserver") == "mailserver"

    def test_invalid_rejected(self):
        with pytest.raises(typer.BadParameter):
            _validate_host("not valid!")


class TestValidateIp:
    def test_valid_ipv4(self):
        assert _validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert _validate_ip("::1") == "::1"

    def test_hostname_rejected(self):
        with pytest.raises(typer.BadParameter):
            _validate_ip("mail.example.com")

    def test_empty_rejected(self):
        with pytest.raises(typer.BadParameter):
            _validate_ip("")


class TestCliCommands:
    def test_version_flag(self):
        result = _runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "mailvalidator" in result.output

    def test_cmd_mx(self):
        with (
            patch("mailvalidator.cli.check_mx", return_value=make_mx_result()) as mock,
            patch("mailvalidator.cli.print_mx"),
        ):
            result = _runner.invoke(app, ["mx", "example.com"])
        assert result.exit_code == 0
        mock.assert_called_once_with("example.com")

    def test_cmd_mx_invalid_domain(self):
        assert _runner.invoke(app, ["mx", "notadomain"]).exit_code != 0

    def test_cmd_spf(self):
        with (
            patch(
                "mailvalidator.cli.check_spf",
                return_value=make_simple_result(SPFResult),
            ),
            patch("mailvalidator.cli.print_spf"),
        ):
            assert _runner.invoke(app, ["spf", "example.com"]).exit_code == 0

    def test_cmd_dmarc(self):
        with (
            patch(
                "mailvalidator.cli.check_dmarc",
                return_value=make_simple_result(DMARCResult),
            ),
            patch("mailvalidator.cli.print_dmarc"),
        ):
            assert _runner.invoke(app, ["dmarc", "example.com"]).exit_code == 0

    def test_cmd_dkim(self):
        with (
            patch(
                "mailvalidator.cli.check_dkim",
                return_value=make_simple_result(DKIMResult),
            ),
            patch("mailvalidator.cli.print_dkim"),
        ):
            assert _runner.invoke(app, ["dkim", "example.com"]).exit_code == 0

    def test_cmd_bimi(self):
        with (
            patch(
                "mailvalidator.cli.check_bimi",
                return_value=make_simple_result(BIMIResult),
            ),
            patch("mailvalidator.cli.print_bimi"),
        ):
            assert _runner.invoke(app, ["bimi", "example.com"]).exit_code == 0

    def test_cmd_tlsrpt(self):
        with (
            patch(
                "mailvalidator.cli.check_tlsrpt",
                return_value=make_simple_result(TLSRPTResult),
            ),
            patch("mailvalidator.cli.print_tlsrpt"),
        ):
            assert _runner.invoke(app, ["tlsrpt", "example.com"]).exit_code == 0

    def test_cmd_mta_sts(self):
        with (
            patch(
                "mailvalidator.cli.check_mta_sts",
                return_value=make_simple_result(MTASTSResult),
            ),
            patch("mailvalidator.cli.print_mta_sts"),
        ):
            assert _runner.invoke(app, ["mta-sts", "example.com"]).exit_code == 0

    def test_cmd_blacklist(self):
        bl = BlacklistResult(ip="1.2.3.4")
        bl.total_checked = 5
        bl.listed_on = []
        bl.checks = []
        with (
            patch("mailvalidator.cli.check_blacklist", return_value=bl),
            patch("mailvalidator.cli.print_blacklist"),
        ):
            assert _runner.invoke(app, ["blacklist", "1.2.3.4"]).exit_code == 0

    def test_cmd_blacklist_invalid_ip(self):
        assert _runner.invoke(app, ["blacklist", "notanip"]).exit_code != 0

    def test_cmd_smtp(self):
        r = SMTPDiagResult(host="mail.example.com", port=25)
        r.checks = []
        with (
            patch("mailvalidator.cli.check_smtp", return_value=r),
            patch("mailvalidator.cli.print_smtp"),
        ):
            assert _runner.invoke(app, ["smtp", "mail.example.com"]).exit_code == 0

    def test_cmd_smtp_invalid_host(self):
        assert _runner.invoke(app, ["smtp", "not valid!"]).exit_code != 0

    def test_cmd_check(self):
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report"),
        ):
            assert _runner.invoke(app, ["check", "example.com"]).exit_code == 0

    def test_cmd_check_no_smtp_flag(self):
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ) as mock,
            patch("mailvalidator.cli.print_full_report"),
        ):
            _runner.invoke(app, ["check", "example.com", "--no-smtp"])
        assert mock.call_args.kwargs.get("run_smtp") is False

    def test_cmd_check_no_blacklist_flag(self):
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ) as mock,
            patch("mailvalidator.cli.print_full_report"),
        ):
            _runner.invoke(app, ["check", "example.com", "--no-blacklist"])
        assert mock.call_args.kwargs.get("run_blacklist") is False

    def test_cmd_check_progress_cb_invoked(self):
        def _fake_assess(
            domain, *, smtp_port, run_smtp, run_blacklist, run_dnssec, progress_cb
        ):
            if progress_cb:
                progress_cb("Checking MX records…")
            return FullReport(domain=domain)

        with (
            patch("mailvalidator.cli.assess", side_effect=_fake_assess),
            patch("mailvalidator.cli.print_full_report"),
        ):
            assert _runner.invoke(app, ["check", "example.com"]).exit_code == 0

    def test_cmd_check_no_dnssec_flag(self):
        """--no-dnssec passes run_dnssec=False to assess."""
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ) as mock,
            patch("mailvalidator.cli.print_full_report"),
        ):
            _runner.invoke(app, ["check", "example.com", "--no-dnssec"])
        assert mock.call_args.kwargs.get("run_dnssec") is False

    def test_cmd_check_output_txt(self, tmp_path):
        """--output FILE.txt calls save_report with the correct path."""
        dest = str(tmp_path / "out.txt")
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report"),
            patch("mailvalidator.cli.save_report") as mock_save,
        ):
            result = _runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 0
        mock_save.assert_called_once_with(dest)

    def test_cmd_check_output_svg(self, tmp_path):
        dest = str(tmp_path / "out.svg")
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report"),
            patch("mailvalidator.cli.save_report") as mock_save,
        ):
            result = _runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 0
        mock_save.assert_called_once_with(dest)

    def test_cmd_check_output_html(self, tmp_path):
        dest = str(tmp_path / "out.html")
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report"),
            patch("mailvalidator.cli.save_report") as mock_save,
        ):
            result = _runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 0
        mock_save.assert_called_once_with(dest)

    def test_cmd_check_output_invalid_extension_exits_1(self, tmp_path):
        """save_report raising ValueError must exit with code 1."""
        dest = str(tmp_path / "out.pdf")
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report"),
            patch(
                "mailvalidator.cli.save_report",
                side_effect=ValueError("Unsupported export format"),
            ),
        ):
            result = _runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 1

    def test_cmd_check_output_oserror_exits_1(self, tmp_path):
        """OSError from save_report (e.g. permission denied) must exit with code 1."""
        dest = str(tmp_path / "out.txt")
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report"),
            patch(
                "mailvalidator.cli.save_report",
                side_effect=OSError("permission denied"),
            ),
        ):
            result = _runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 1

    def test_cmd_check_no_output_does_not_call_save_report(self):
        """When --output is omitted, save_report is never called."""
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report"),
            patch("mailvalidator.cli.save_report") as mock_save,
        ):
            _runner.invoke(app, ["check", "example.com"])
        mock_save.assert_not_called()


class TestCmdDnssec:
    def test_cmd_dnssec_no_mx(self):
        """dnssec sub-command: prints domain section; skips MX when no records."""
        from mailvalidator.models import DNSSECResult, MXResult

        dnssec_result = DNSSECResult(domain="example.com")
        mx_result = MXResult(domain="example.com")

        with (
            patch("mailvalidator.cli.check_dnssec_domain", return_value=dnssec_result),
            patch("mailvalidator.cli.check_mx", return_value=mx_result),
            patch("mailvalidator.cli.print_dnssec_domain") as mock_print_d,
            patch("mailvalidator.cli.print_dnssec_mx") as mock_print_mx,
        ):
            result = _runner.invoke(app, ["dnssec", "example.com"])
        assert result.exit_code == 0
        mock_print_d.assert_called_once_with(dnssec_result)
        mock_print_mx.assert_not_called()

    def test_cmd_dnssec_with_mx(self):
        """dnssec sub-command: prints both domain and MX sections when MX present."""
        from mailvalidator.models import DNSSECResult, MXRecord, MXResult

        dnssec_result = DNSSECResult(domain="example.com")
        mx_dnssec_result = DNSSECResult(domain="example.com")
        mx_result = MXResult(domain="example.com")
        mx_result.records = [MXRecord(priority=10, exchange="mx1.example.com")]

        with (
            patch("mailvalidator.cli.check_dnssec_domain", return_value=dnssec_result),
            patch("mailvalidator.cli.check_mx", return_value=mx_result),
            patch("mailvalidator.cli.check_dnssec_mx", return_value=mx_dnssec_result),
            patch("mailvalidator.cli.print_dnssec_domain") as mock_print_d,
            patch("mailvalidator.cli.print_dnssec_mx") as mock_print_mx,
        ):
            result = _runner.invoke(app, ["dnssec", "example.com"])
        assert result.exit_code == 0
        mock_print_d.assert_called_once_with(dnssec_result)
        mock_print_mx.assert_called_once_with(mx_dnssec_result)


class TestJsonFlag:
    """--json flag outputs valid JSON and skips the Rich reporter."""

    def _valid_json(self, output: str) -> dict:
        import json

        return json.loads(output)

    def test_check_json(self):
        with (
            patch(
                "mailvalidator.cli.assess",
                return_value=FullReport(domain="example.com"),
            ),
            patch("mailvalidator.cli.print_full_report") as mock_print,
        ):
            result = _runner.invoke(app, ["check", "example.com", "--json"])
        assert result.exit_code == 0
        data = self._valid_json(result.output)
        assert data["domain"] == "example.com"
        mock_print.assert_not_called()

    def test_mx_json(self):
        with (
            patch("mailvalidator.cli.check_mx", return_value=make_mx_result()),
            patch("mailvalidator.cli.print_mx") as mock_print,
        ):
            result = _runner.invoke(app, ["mx", "example.com", "--json"])
        assert result.exit_code == 0
        data = self._valid_json(result.output)
        assert "domain" in data
        mock_print.assert_not_called()

    def test_spf_json(self):
        with (
            patch("mailvalidator.cli.check_spf", return_value=make_simple_result(SPFResult)),
            patch("mailvalidator.cli.print_spf") as mock_print,
        ):
            result = _runner.invoke(app, ["spf", "example.com", "--json"])
        assert result.exit_code == 0
        self._valid_json(result.output)
        mock_print.assert_not_called()

    def test_dmarc_json(self):
        with (
            patch("mailvalidator.cli.check_dmarc", return_value=make_simple_result(DMARCResult)),
            patch("mailvalidator.cli.print_dmarc") as mock_print,
        ):
            result = _runner.invoke(app, ["dmarc", "example.com", "--json"])
        assert result.exit_code == 0
        self._valid_json(result.output)
        mock_print.assert_not_called()

    def test_dkim_json(self):
        with (
            patch("mailvalidator.cli.check_dkim", return_value=make_simple_result(DKIMResult)),
            patch("mailvalidator.cli.print_dkim") as mock_print,
        ):
            result = _runner.invoke(app, ["dkim", "example.com", "--json"])
        assert result.exit_code == 0
        self._valid_json(result.output)
        mock_print.assert_not_called()

    def test_bimi_json(self):
        with (
            patch("mailvalidator.cli.check_bimi", return_value=make_simple_result(BIMIResult)),
            patch("mailvalidator.cli.print_bimi") as mock_print,
        ):
            result = _runner.invoke(app, ["bimi", "example.com", "--json"])
        assert result.exit_code == 0
        self._valid_json(result.output)
        mock_print.assert_not_called()

    def test_tlsrpt_json(self):
        with (
            patch("mailvalidator.cli.check_tlsrpt", return_value=make_simple_result(TLSRPTResult)),
            patch("mailvalidator.cli.print_tlsrpt") as mock_print,
        ):
            result = _runner.invoke(app, ["tlsrpt", "example.com", "--json"])
        assert result.exit_code == 0
        self._valid_json(result.output)
        mock_print.assert_not_called()

    def test_mta_sts_json(self):
        with (
            patch("mailvalidator.cli.check_mta_sts", return_value=make_simple_result(MTASTSResult)),
            patch("mailvalidator.cli.print_mta_sts") as mock_print,
        ):
            result = _runner.invoke(app, ["mta-sts", "example.com", "--json"])
        assert result.exit_code == 0
        self._valid_json(result.output)
        mock_print.assert_not_called()

    def test_blacklist_json(self):
        bl = BlacklistResult(ip="1.2.3.4")
        bl.total_checked = 5
        bl.listed_on = []
        bl.checks = []
        with (
            patch("mailvalidator.cli.check_blacklist", return_value=bl),
            patch("mailvalidator.cli.print_blacklist") as mock_print,
        ):
            result = _runner.invoke(app, ["blacklist", "1.2.3.4", "--json"])
        assert result.exit_code == 0
        data = self._valid_json(result.output)
        assert data["ip"] == "1.2.3.4"
        mock_print.assert_not_called()

    def test_smtp_json(self):
        r = SMTPDiagResult(host="mail.example.com", port=25)
        r.checks = []
        with (
            patch("mailvalidator.cli.check_smtp", return_value=r),
            patch("mailvalidator.cli.print_smtp") as mock_print,
        ):
            result = _runner.invoke(app, ["smtp", "mail.example.com", "--json"])
        assert result.exit_code == 0
        data = self._valid_json(result.output)
        assert data["host"] == "mail.example.com"
        mock_print.assert_not_called()

    def test_dnssec_json_no_mx(self):
        from mailvalidator.models import DNSSECResult, MXResult

        with (
            patch("mailvalidator.cli.check_dnssec_domain", return_value=DNSSECResult(domain="example.com")),
            patch("mailvalidator.cli.check_mx", return_value=MXResult(domain="example.com")),
            patch("mailvalidator.cli.print_dnssec_domain") as mock_print,
        ):
            result = _runner.invoke(app, ["dnssec", "example.com", "--json"])
        assert result.exit_code == 0
        data = self._valid_json(result.output)
        assert "domain" in data
        assert "mx" not in data
        mock_print.assert_not_called()

    def test_dnssec_json_with_mx(self):
        from mailvalidator.models import DNSSECResult, MXRecord, MXResult

        mx_result = MXResult(domain="example.com")
        mx_result.records = [MXRecord(priority=10, exchange="mx1.example.com")]
        with (
            patch("mailvalidator.cli.check_dnssec_domain", return_value=DNSSECResult(domain="example.com")),
            patch("mailvalidator.cli.check_mx", return_value=mx_result),
            patch("mailvalidator.cli.check_dnssec_mx", return_value=DNSSECResult(domain="example.com")),
            patch("mailvalidator.cli.print_dnssec_domain") as mock_print,
        ):
            result = _runner.invoke(app, ["dnssec", "example.com", "--json"])
        assert result.exit_code == 0
        data = self._valid_json(result.output)
        assert "domain" in data
        assert "mx" in data
        mock_print.assert_not_called()
