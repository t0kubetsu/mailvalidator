"""DNS helper utilities built on dnspython.

All public functions return plain Python types (lists of strings) and swallow
DNS exceptions so callers never need to handle resolver errors directly.
A two-server public-DNS fallback (8.8.8.8 / 1.1.1.1) is used when the
system resolver is unavailable or returns no nameservers.

:func:`resolve` has an optional *raise_nxdomain* parameter for callers that
need to distinguish between "domain does not exist" (NXDOMAIN) and "domain
exists but has no records of this type" (NOERROR with empty answer).  The
DKIM base-node check is the primary consumer of this distinction.
"""

from __future__ import annotations

import socket

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename

_FALLBACK_NS = ["8.8.8.8", "1.1.1.1"]


def _make_resolver(nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    """Return a configured :class:`dns.resolver.Resolver`.

    If *nameservers* is provided those addresses are used directly.  Otherwise
    the system resolver is tried; if it has no nameservers configured the
    public fallbacks (8.8.8.8 / 1.1.1.1) are used instead.

    :param nameservers: Optional list of resolver IP addresses to use.
    :returns: A ready-to-use :class:`dns.resolver.Resolver` instance.
    """
    try:
        resolver = dns.resolver.Resolver()
    except Exception:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(_FALLBACK_NS)

    if nameservers:
        resolver.nameservers = nameservers
    elif not getattr(resolver, "nameservers", None):
        resolver.nameservers = list(_FALLBACK_NS)  # pragma: no cover

    return resolver


def resolve(
    name: str,
    rdtype: str,
    nameservers: list[str] | None = None,
    *,
    raise_nxdomain: bool = False,
) -> list[str] | None:
    """Resolve *name* for *rdtype* and return rdata values as strings.

    :param name: DNS name to query (e.g. ``"_dmarc.example.com"``).
    :param rdtype: Record type string (e.g. ``"TXT"``, ``"MX"``, ``"TLSA"``).
    :param nameservers: Optional list of resolver IP addresses.  When omitted
        the system resolver (or public fallback) is used.
    :param raise_nxdomain: When ``True``, return ``None`` instead of ``[]``
        on NXDOMAIN so callers can distinguish "domain does not exist" from
        "domain exists but has no records of this type".  Defaults to
        ``False`` for backward compatibility.
    :returns: Zero or more ``to_text()`` representations of the answer
        records.  Returns ``[]`` on NOERROR/empty answer or any DNS error.
        Returns ``None`` only when *raise_nxdomain* is ``True`` and the
        queried name does not exist.
    :rtype: list[str] | None
    """
    resolver = _make_resolver(nameservers)
    try:
        answer = resolver.resolve(name, rdtype, raise_on_no_answer=False)
        if answer.rrset is None:
            return []
        return [r.to_text() for r in answer.rrset]
    except dns.resolver.NXDOMAIN:
        return None if raise_nxdomain else []
    except (
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return []


def get_authoritative_ns(domain: str) -> list[str]:
    """Return IP addresses of the authoritative name servers for *domain*.

    Performs an NS query followed by A/AAAA lookups for each NS hostname.

    :param domain: Domain name to look up.
    :returns: Unique IP address strings for the authoritative name servers.
        Returns an empty list when any step fails.
    :rtype: list[str]
    """
    resolver = _make_resolver()
    ns_names: list[str] = []
    try:
        answer = resolver.resolve(domain, "NS", raise_on_no_answer=False)
        if answer.rrset:
            ns_names = [r.to_text().rstrip(".") for r in answer.rrset]
    except dns.exception.DNSException:
        pass

    ips: list[str] = []
    for ns in ns_names:
        try:
            for info in socket.getaddrinfo(ns, 53, proto=socket.IPPROTO_UDP):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass

    return ips


def reverse_lookup(ip: str) -> str:
    """Return the PTR record for *ip*, or an empty string on failure.

    :param ip: IPv4 or IPv6 address string.
    :returns: The PTR hostname with the trailing dot stripped, or ``""``
        if no PTR record exists or the lookup fails.
    :rtype: str
    """
    resolver = _make_resolver()
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, "PTR", raise_on_no_answer=False)
        if answers.rrset:
            return answers.rrset[0].to_text().rstrip(".")
    except dns.exception.DNSException:
        pass
    return ""


def resolve_a(name: str) -> list[str]:
    """Resolve both A and AAAA records for *name* and return all IP strings.

    :param name: Hostname to resolve.
    :returns: Combined list of IPv4 and IPv6 address strings.
    :rtype: list[str]
    """
    ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        result = resolve(name, rdtype)
        if result:
            ips.extend(result)
    return ips
