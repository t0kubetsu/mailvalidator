"""Tests for mailvalidator/checks/bimi.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.bimi import check_bimi
from mailvalidator.models import Status


class TestBIMI:
    def test_valid_record(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(c.status == Status.OK and "Logo" in c.name for c in result.checks)

    def test_http_logo_error(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=http://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(c.status == Status.ERROR and "Logo" in c.name for c in result.checks)


class TestBIMIExtra:
    def test_not_found(self):
        with patch("mailvalidator.checks.bimi.resolve", return_value=[]):
            result = check_bimi("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_unknown_version_not_found(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI2; l=https://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_bad_version_via_internal_validator(self):
        from mailvalidator.checks.bimi import _validate
        from mailvalidator.models import BIMIResult

        result = BIMIResult(domain="example.com")
        _validate({"v": "BIMI2", "l": "https://example.com/logo.svg"}, result)
        assert any(
            c.name == "Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_logo_url_warns(self):
        with patch("mailvalidator.checks.bimi.resolve", return_value=['"v=BIMI1"']):
            result = check_bimi("example.com")
        assert any(
            c.name == "Logo URL (l=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_non_svg_logo_warns(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.png"'],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Logo URL (l=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_svg_gz_logo_ok(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.svg.gz"'],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Logo URL (l=)" and c.status == Status.OK for c in result.checks
        )

    def test_authority_evidence_present(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"'
            ],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Authority Evidence (a=)" and c.value for c in result.checks
        )

    def test_authority_evidence_missing_info(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Authority Evidence (a=)" and c.status == Status.INFO
            for c in result.checks
        )
