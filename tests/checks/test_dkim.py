"""Tests for mailvalidator/checks/dkim.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.dkim import check_dkim
from mailvalidator.models import Status


class TestDKIM:
    def test_base_node_ok(self):
        with patch("mailvalidator.checks.dkim.resolve", return_value=[]):
            result = check_dkim("example.com")
        assert any(
            c.name == "DKIM Base Node" and c.status == Status.OK for c in result.checks
        )

    def test_base_node_nxdomain(self):
        with patch("mailvalidator.checks.dkim.resolve", return_value=None):
            result = check_dkim("example.com")
        assert any(
            c.name == "DKIM Base Node" and c.status == Status.ERROR
            for c in result.checks
        )
