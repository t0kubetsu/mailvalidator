"""Tests for mailvalidator/dns_utils.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mailvalidator.dns_utils import (
    get_authoritative_ns,
    resolve,
    resolve_a,
    reverse_lookup,
)


class TestDnsUtils:
    def test_resolve_returns_list_on_success(self):
        mock_rrset = MagicMock()
        mock_rrset.__iter__ = MagicMock(
            return_value=iter([MagicMock(to_text=lambda: "10 mail.example.com.")])
        )
        mock_answer = MagicMock()
        mock_answer.rrset = mock_rrset
        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.return_value = mock_answer
            result = resolve("example.com", "MX")
        assert isinstance(result, list)

    def test_resolve_nxdomain_returns_empty_by_default(self):
        import dns.resolver

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
            result = resolve("nonexistent.invalid", "TXT")
        assert result == []

    def test_resolve_nxdomain_returns_none_when_raise_nxdomain(self):
        import dns.resolver

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
            result = resolve("nonexistent.invalid", "TXT", raise_nxdomain=True)
        assert result is None

    def test_resolve_dns_exception_returns_empty(self):
        import dns.exception

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = dns.exception.DNSException()
            result = resolve("example.com", "TXT")
        assert result == []

    def test_resolve_empty_rrset_returns_empty(self):
        mock_answer = MagicMock()
        mock_answer.rrset = None
        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.return_value = mock_answer
            result = resolve("example.com", "TXT")
        assert result == []

    def test_reverse_lookup_returns_empty_on_error(self):
        import dns.exception

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = dns.exception.DNSException()
            result = reverse_lookup("1.2.3.4")
        assert result == ""

    def test_resolve_a_combines_a_and_aaaa(self):
        def _fake_resolve(name, rdtype, **kwargs):
            mock = MagicMock()
            if rdtype == "A":
                mock.rrset = [MagicMock(to_text=lambda: "1.2.3.4")]
            else:
                mock.rrset = [MagicMock(to_text=lambda: "2001:db8::1")]
            return mock

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = _fake_resolve
            result = resolve_a("mail.example.com")
        assert "1.2.3.4" in result
        assert "2001:db8::1" in result


class TestDnsUtilsExtra:
    def test_make_resolver_falls_back_when_configure_raises(self):
        import dns.resolver

        call_count = [0]
        real_resolver = dns.resolver.Resolver

        def _patched_resolver(configure=True):
            call_count[0] += 1
            if configure is True and call_count[0] == 1:
                raise Exception("no resolv.conf")
            r = real_resolver(configure=False)
            r.nameservers = ["8.8.8.8"]
            return r

        with patch(
            "mailvalidator.dns_utils.dns.resolver.Resolver",
            side_effect=_patched_resolver,
        ):
            result = resolve("example.com", "TXT")
        assert isinstance(result, list)

    def test_get_authoritative_ns_dns_exception(self):
        import dns.exception

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = dns.exception.DNSException()
            result = get_authoritative_ns("example.com")
        assert result == []

    def test_get_authoritative_ns_socket_error(self):
        import socket as _socket

        mock_rr = MagicMock()
        mock_rr.to_text.return_value = "ns1.example.com."
        mock_answer = MagicMock()
        mock_answer.rrset = [mock_rr]
        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.return_value = mock_answer
            with patch(
                "mailvalidator.dns_utils.socket.getaddrinfo",
                side_effect=_socket.gaierror("no address"),
            ):
                result = get_authoritative_ns("example.com")
        assert result == []

    def test_reverse_lookup_returns_hostname(self):
        mock_rrset = MagicMock()
        mock_rrset.__getitem__ = MagicMock(
            return_value=MagicMock(to_text=lambda: "mail.example.com.")
        )
        mock_answer = MagicMock()
        mock_answer.rrset = mock_rrset
        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.return_value = mock_answer
            result = reverse_lookup("1.2.3.4")
        assert result == "mail.example.com"

    def test_resolve_noerror_no_rrset_returns_empty(self):
        mock_answer = MagicMock()
        mock_answer.rrset = None
        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.return_value = mock_answer
            assert resolve("example.com", "CAA") == []


class TestDnsUtilsRemaining:
    def test_make_resolver_uses_explicit_nameservers(self):
        """Explicit nameservers are assigned to the resolver (line 44)."""
        from mailvalidator.dns_utils import _make_resolver

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            instance = MagicMock()
            MockResolver.return_value = instance
            r = _make_resolver(nameservers=["1.1.1.1", "8.8.8.8"])
        assert r.nameservers == ["1.1.1.1", "8.8.8.8"]

    def test_get_authoritative_ns_returns_ips(self):
        mock_rr = MagicMock()
        mock_rr.to_text.return_value = "ns1.example.com."
        mock_answer = MagicMock()
        mock_answer.rrset = [mock_rr]

        def _fake_getaddrinfo(host, port, proto):
            return [(None, None, None, None, ("1.2.3.4", 53))]

        with patch("mailvalidator.dns_utils.dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.return_value = mock_answer
            with patch(
                "mailvalidator.dns_utils.socket.getaddrinfo",
                side_effect=_fake_getaddrinfo,
            ):
                result = get_authoritative_ns("example.com")
        assert "1.2.3.4" in result
