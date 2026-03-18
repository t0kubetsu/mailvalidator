"""Tests for mailvalidator/checks/tlsrpt.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.tlsrpt import check_tlsrpt
from mailvalidator.models import Status


class TestTLSRPT:
    def test_valid(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("mailvalidator.checks.tlsrpt.resolve", return_value=[]):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)


class TestTLSRPTExtra:
    def test_unknown_version_not_found(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv2; rua=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_bad_version_via_internal_validator(self):
        from mailvalidator.checks.tlsrpt import _validate
        from mailvalidator.models import TLSRPTResult

        result = TLSRPTResult(domain="example.com")
        _validate({"v": "TLSRPTv2", "rua": "mailto:tls@example.com"}, result)
        assert any(
            c.name == "Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_rua_error(self):
        with patch("mailvalidator.checks.tlsrpt.resolve", return_value=['"v=TLSRPTv1"']):
            result = check_tlsrpt("example.com")
        assert any(
            "rua" in c.name.lower() and c.status == Status.ERROR for c in result.checks
        )

    def test_https_rua_ok(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=https://reports.example.com/tls"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI" and c.status == Status.OK for c in result.checks
        )

    def test_invalid_rua_scheme_warns(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=http://reports.example.com/tls"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_multiple_rua_uris(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=[
                '"v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com/tls"'
            ],
        ):
            result = check_tlsrpt("example.com")
        assert len([c for c in result.checks if c.name == "Reporting URI"]) == 2
