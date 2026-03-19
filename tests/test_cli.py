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
        def _fake_assess(domain, *, smtp_port, run_smtp, run_blacklist, progress_cb):
            if progress_cb:
                progress_cb("Checking MX records…")
            return FullReport(domain=domain)

        with (
            patch("mailvalidator.cli.assess", side_effect=_fake_assess),
            patch("mailvalidator.cli.print_full_report"),
        ):
            assert _runner.invoke(app, ["check", "example.com"]).exit_code == 0
