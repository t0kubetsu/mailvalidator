"""Tests for mailvalidator/checks/mta_sts.py."""

from __future__ import annotations

import urllib.error
from unittest.mock import patch

from mailvalidator.checks.mta_sts import (
    _fetch_policy,
    _parse_policy_file,
    _validate_policy,
    check_mta_sts,
)
from mailvalidator.models import MTASTSResult, Status


class TestMTASTS:
    def test_valid(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.OK for c in result.checks
        )

    def test_not_found(self):
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[]):
            result = check_mta_sts("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)


class TestMTASTSExtra:
    def test_bad_dns_version_error(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                with patch(
                    "mailvalidator.checks.mta_sts._parse_dns_record",
                    return_value={"v": "STSv2", "id": "20240101T000000"},
                ):
                    result = check_mta_sts("example.com")
        assert any(
            c.name == "DNS Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_id_error(self):
        dns_record = '"v=STSv1"'
        policy_text = (
            "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Record ID (id=)" and c.status == Status.ERROR
            for c in result.checks
        )

    def test_policy_fetch_failure(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=("", "connection refused"),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy File" and c.status == Status.ERROR for c in result.checks
        )

    def test_testing_mode_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: testing\nmax_age: 604800\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_none_mode_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: none\nmax_age: 604800\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_short_max_age_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: enforce\nmax_age: 3600\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "max_age" and c.status == Status.WARNING for c in result.checks
        )

    def test_invalid_max_age_error(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: enforce\nmax_age: notanumber\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "max_age" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_max_age_error(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = "version: STSv1\nmode: enforce\nmx: mail.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "max_age" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_mx_entries_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = "version: STSv1\nmode: enforce\nmax_age: 604800"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "MX Entries" and c.status == Status.WARNING for c in result.checks
        )

    def test_multiple_mx_entries(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx1.example.com\nmx: mx2.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        mx_check = next(c for c in result.checks if c.name == "MX Entries")
        assert "mx1.example.com" in mx_check.value
        assert "mx2.example.com" in mx_check.value


class TestMTASTSCoverage:
    def test_parse_policy_file_multi_mx(self):
        text = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx1.example.com\nmx: mx2.example.com"
        policy = _parse_policy_file(text)
        assert policy["mx"] == ["mx1.example.com", "mx2.example.com"]

    def test_parse_policy_file_skips_blank_lines(self):
        policy = _parse_policy_file("\nmode: enforce\n\nmax_age: 604800\n")
        assert "mode" in policy
        assert "max_age" in policy

    def test_fetch_policy_url_error(self):
        with patch(
            "mailvalidator.checks.mta_sts.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            text, err = _fetch_policy(
                "https://mta-sts.example.com/.well-known/mta-sts.txt"
            )
        assert text == ""
        assert "connection refused" in err

    def test_fetch_policy_generic_exception(self):
        with patch(
            "mailvalidator.checks.mta_sts.urllib.request.urlopen",
            side_effect=RuntimeError("unexpected"),
        ):
            text, err = _fetch_policy(
                "https://mta-sts.example.com/.well-known/mta-sts.txt"
            )
        assert text == ""
        assert "unexpected" in err


class TestMTASTSRemaining:
    def test_fetch_policy_success_path(self):
        mock_response = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        mock_response.read.return_value = b"version: STSv1\nmode: enforce"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = __import__(
            "unittest.mock", fromlist=["MagicMock"]
        ).MagicMock(return_value=False)
        with patch(
            "mailvalidator.checks.mta_sts.urllib.request.urlopen",
            return_value=mock_response,
        ):
            text, err = _fetch_policy(
                "https://mta-sts.example.com/.well-known/mta-sts.txt"
            )
        assert err == ""
        assert "STSv1" in text

    def test_validate_policy_mx_as_string_coerced_to_list(self):
        result = MTASTSResult(domain="example.com")
        _validate_policy(
            {"mode": "enforce", "max_age": "604800", "mx": "mail.example.com"}, result
        )
        mx_check = next(c for c in result.checks if c.name == "MX Entries")
        assert mx_check.status == Status.OK
        assert "mail.example.com" in mx_check.value
