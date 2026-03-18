"""Tests for mailvalidator/assessor.py."""

from __future__ import annotations

import socket as _socket
from unittest.mock import MagicMock, patch

from mailvalidator.assessor import _resolve_mx_ips, assess
from mailvalidator.models import (
    BIMIResult,
    DMARCResult,
    DKIMResult,
    FullReport,
    MTASTSResult,
    MXRecord,
    SPFResult,
    TLSRPTResult,
)
from tests.conftest import make_mx_result, make_simple_result


class TestResolveMxIps:
    def test_extracts_ipv4(self):
        rec = MXRecord(
            priority=10, exchange="mail.example.com", ip_addresses=["1.2.3.4"]
        )
        assert _resolve_mx_ips([rec]) == ["1.2.3.4"]

    def test_skips_ipv6(self):
        rec = MXRecord(
            priority=10, exchange="mail.example.com", ip_addresses=["2001:db8::1"]
        )
        assert _resolve_mx_ips([rec]) == []

    def test_deduplicates(self):
        r1 = MXRecord(priority=10, exchange="mx1.example.com", ip_addresses=["1.2.3.4"])
        r2 = MXRecord(priority=20, exchange="mx2.example.com", ip_addresses=["1.2.3.4"])
        assert _resolve_mx_ips([r1, r2]) == ["1.2.3.4"]

    def test_empty_records(self):
        assert _resolve_mx_ips([]) == []

    def test_multiple_ips_per_record(self):
        rec = MXRecord(
            priority=10,
            exchange="mail.example.com",
            ip_addresses=["1.2.3.4", "5.6.7.8"],
        )
        result = _resolve_mx_ips([rec])
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result


class TestAssess:
    def _patches(self):
        return dict(
            check_mx=make_mx_result(),
            check_spf=make_simple_result(SPFResult),
            check_dmarc=make_simple_result(DMARCResult),
            check_dkim=make_simple_result(DKIMResult),
            check_bimi=make_simple_result(BIMIResult),
            check_tlsrpt=make_simple_result(TLSRPTResult),
            check_mta_sts=make_simple_result(MTASTSResult),
        )

    def _ctx(self, extra=None):
        """Return a context manager that patches all check functions."""
        p = self._patches()
        if extra:
            p.update(extra)
        # patch.multiple needs callables; wrap plain objects in MagicMock(return_value=...)
        mocks = {}
        for k, v in p.items():
            if isinstance(v, MagicMock):
                mocks[k] = v
            else:
                mocks[k] = MagicMock(return_value=v)
        return patch.multiple("mailvalidator.assessor", **mocks)

    def test_returns_full_report(self):
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            report = assess("example.com")
        assert isinstance(report, FullReport)
        assert report.domain == "example.com"

    def test_progress_cb_called(self):
        calls = []
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            assess("example.com", progress_cb=calls.append)
        assert len(calls) > 0
        assert all(isinstance(c, str) for c in calls)

    def test_smtp_skipped_when_run_smtp_false(self):
        mock_smtp = MagicMock()
        with self._ctx(
            {
                "check_smtp": mock_smtp,
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            assess("example.com", run_smtp=False)
        mock_smtp.assert_not_called()

    def test_blacklist_skipped_when_run_blacklist_false(self):
        mock_bl = MagicMock()
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": mock_bl,
            }
        ):
            assess("example.com", run_blacklist=False)
        mock_bl.assert_not_called()

    def test_smtp_called_for_at_most_three_mx(self):
        records = [
            MXRecord(
                priority=i * 10,
                exchange=f"mx{i}.example.com",
                ip_addresses=[f"1.2.3.{i}"],
            )
            for i in range(1, 5)
        ]
        mock_smtp = MagicMock(return_value=MagicMock())
        with self._ctx(
            {
                "check_smtp": mock_smtp,
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                assess("example.com")
        assert mock_smtp.call_count == 3

    def test_blacklist_uses_first_mx_ip(self):
        records = [
            MXRecord(priority=10, exchange="mail.example.com", ip_addresses=["9.9.9.9"])
        ]
        mock_bl = MagicMock(return_value=MagicMock())
        mock_smtp = MagicMock(return_value=MagicMock())
        with self._ctx({"check_smtp": mock_smtp, "check_blacklist": mock_bl}):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                assess("example.com")
        mock_bl.assert_called_once_with("9.9.9.9")

    def test_blacklist_falls_back_to_a_record(self):
        """When MX has no IPv4 IPs, blacklist uses gethostbyname(domain)."""
        mock_bl = MagicMock(return_value=MagicMock())
        # make_mx_result() returns empty records → no IPv4 → fallback path
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": mock_bl,
            }
        ):
            with patch(
                "mailvalidator.assessor.socket.gethostbyname", return_value="3.3.3.3"
            ):
                assess("example.com")
        mock_bl.assert_called_once_with("3.3.3.3")

    def test_blacklist_skipped_when_gethostbyname_fails(self):
        mock_bl = MagicMock()
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": mock_bl,
            }
        ):
            with patch(
                "mailvalidator.assessor.socket.gethostbyname",
                side_effect=_socket.gaierror("no address"),
            ):
                report = assess("example.com")
        mock_bl.assert_not_called()
        assert report.blacklist is None
