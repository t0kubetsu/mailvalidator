"""Tests for mailvalidator/checks/dmarc.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.dmarc import check_dmarc
from mailvalidator.models import Status


class TestDMARC:
    def test_reject_policy(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'],
        ):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.OK for c in result.checks
        )

    def test_none_policy_warning(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve", return_value=['"v=DMARC1; p=none"']
        ):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_missing_rua_warning(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve", return_value=['"v=DMARC1; p=reject"']
        ):
            result = check_dmarc("example.com")
        assert any(
            "rua" in c.name.lower() and c.status == Status.WARNING
            for c in result.checks
        )


class TestDMARCExtra:
    def test_not_found(self):
        with patch("mailvalidator.checks.dmarc.resolve", return_value=[]):
            result = check_dmarc("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_multiple_records_error(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=['"v=DMARC1; p=reject"', '"v=DMARC1; p=none"'],
        ):
            result = check_dmarc("example.com")
        assert any(
            "Multiple" in c.name and c.status == Status.ERROR for c in result.checks
        )

    def test_quarantine_policy(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=['"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"'],
        ):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.OK for c in result.checks
        )

    def test_invalid_policy_error(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve", return_value=['"v=DMARC1; p=invalid"']
        ):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.ERROR for c in result.checks
        )

    def test_pct_below_100_warns(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=['"v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com"'],
        ):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Percentage (pct=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_pct_invalid_value_error(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=['"v=DMARC1; p=reject; pct=abc"'],
        ):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Percentage (pct=)" and c.status == Status.ERROR
            for c in result.checks
        )

    def test_subdomain_policy_reported(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=[
                '"v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com"'
            ],
        ):
            result = check_dmarc("example.com")
        assert any(c.name == "Subdomain Policy (sp=)" for c in result.checks)

    def test_ruf_tag_reported(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=[
                '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com"'
            ],
        ):
            result = check_dmarc("example.com")
        assert any(c.name == "Forensic Reports (ruf=)" for c in result.checks)

    def test_strict_adkim_reported(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=[
                '"v=DMARC1; p=reject; adkim=s; rua=mailto:dmarc@example.com"'
            ],
        ):
            result = check_dmarc("example.com")
        assert any(
            c.name == "DKIM Alignment" and c.value == "strict" for c in result.checks
        )
