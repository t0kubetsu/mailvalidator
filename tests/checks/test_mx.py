"""Tests for mailvalidator/checks/mx.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.mx import check_mx
from mailvalidator.models import Status


class TestMX:
    def test_found(self):
        with patch(
            "mailvalidator.checks.mx.resolve", return_value=["10 mail.example.com."]
        ):
            with patch("mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]):
                with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                    result = check_mx("example.com")
        assert len(result.records) == 1
        assert result.records[0].priority == 10
        assert result.records[0].exchange == "mail.example.com"
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("mailvalidator.checks.mx.resolve", return_value=[]):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                result = check_mx("nodomain.invalid")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_sorted_by_priority(self):
        records_raw = ["20 mail2.example.com.", "10 mail1.example.com."]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                with patch("mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]):
                    result = check_mx("example.com")
        assert result.records[0].priority == 10
        assert result.records[1].priority == 20


class TestMXExtra:
    def test_malformed_entry_skipped(self):
        records_raw = ["10 mail.example.com.", "badentry"]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                with patch("mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]):
                    result = check_mx("example.com")
        assert len(result.records) == 1

    def test_duplicate_priority_warns(self):
        records_raw = ["10 mail1.example.com.", "10 mail2.example.com."]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                with patch("mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]):
                    result = check_mx("example.com")
        assert any(
            c.name == "Duplicate Priorities" and c.status == Status.WARNING
            for c in result.checks
        )
