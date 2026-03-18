"""Tests for mailvalidator/checks/blacklist.py."""

from __future__ import annotations

import socket as _socket
from unittest.mock import patch

from mailvalidator.checks.blacklist import _check_single, _reverse_ip, check_blacklist
from mailvalidator.models import Status


class TestBlacklist:
    def test_reverse_ipv4(self):
        assert _reverse_ip("1.2.3.4") == "4.3.2.1"

    def test_reverse_ipv4_loopback(self):
        assert _reverse_ip("127.0.0.1") == "1.0.0.127"

    def test_reverse_ipv6(self):
        result = _reverse_ip("2001:db8::1")
        assert result.endswith(".1.0.0.2")

    def test_reverse_invalid_returns_empty(self):
        assert _reverse_ip("not-an-ip") == ""

    def test_listed_returns_true_for_127_0_0_2(self):
        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname", return_value="127.0.0.2"
        ):
            zone, listed = _check_single("1.2.3.4", "zen.spamhaus.org")
        assert listed is True
        assert zone == "zen.spamhaus.org"

    def test_not_listed_for_127_255_255_255(self):
        """127.255.255.255 (bondedsender.org) must NOT count as listed."""
        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname",
            return_value="127.255.255.255",
        ):
            zone, listed = _check_single("1.1.1.1", "query.bondedsender.org")
        assert listed is False

    def test_not_listed_for_127_0_0_3(self):
        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname", return_value="127.0.0.3"
        ):
            _, listed = _check_single("1.2.3.4", "some.dnsbl.example")
        assert listed is False

    def test_not_listed_on_nxdomain(self):
        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname",
            side_effect=_socket.gaierror("NXDOMAIN"),
        ):
            _, listed = _check_single("1.2.3.4", "zen.spamhaus.org")
        assert listed is False

    def test_invalid_ip_returns_not_listed(self):
        _, listed = _check_single("not-an-ip", "zen.spamhaus.org")
        assert listed is False

    def test_clean_ip_produces_ok_result(self):
        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname",
            side_effect=_socket.gaierror("NXDOMAIN"),
        ):
            result = check_blacklist(
                "1.2.3.4", zones=["zen.spamhaus.org", "bl.spamcop.net"]
            )
        assert result.listed_on == []
        assert any(c.status == Status.OK for c in result.checks)

    def test_listed_ip_produces_error_result(self):
        def _fake(query: str) -> str:
            if "zen.spamhaus.org" in query:
                return "127.0.0.2"
            raise _socket.gaierror("NXDOMAIN")

        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname", side_effect=_fake
        ):
            result = check_blacklist(
                "1.2.3.4", zones=["zen.spamhaus.org", "bl.spamcop.net"]
            )
        assert "zen.spamhaus.org" in result.listed_on
        assert "bl.spamcop.net" not in result.listed_on
        assert any(c.status == Status.ERROR for c in result.checks)

    def test_duplicate_zones_deduplicated(self):
        call_count = [0]

        def _counting(query: str) -> str:
            call_count[0] += 1
            raise _socket.gaierror("NXDOMAIN")

        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname", side_effect=_counting
        ):
            check_blacklist("1.2.3.4", zones=["zen.spamhaus.org", "zen.spamhaus.org"])
        assert call_count[0] == 1

    def test_total_checked_matches_unique_zones(self):
        with patch(
            "mailvalidator.checks.blacklist.socket.gethostbyname",
            side_effect=_socket.gaierror("NXDOMAIN"),
        ):
            result = check_blacklist(
                "1.2.3.4", zones=["a.example", "b.example", "a.example"]
            )
        assert result.total_checked == 2
