"""DNS helper utilities using dnspython."""

from __future__ import annotations

import socket

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename

_FALLBACK_NS = ["8.8.8.8", "1.1.1.1"]


def _make_resolver(nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    """Return a Resolver instance, falling back to public DNS if needed."""
    try:
        resolver = dns.resolver.Resolver()
    except Exception:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(_FALLBACK_NS)

    if nameservers:
        resolver.nameservers = nameservers
    elif not getattr(resolver, "nameservers", None):
        resolver.nameservers = list(_FALLBACK_NS)

    return resolver


def resolve(
    name: str,
    rdtype: str,
    nameservers: list[str] | None = None,
) -> list[str]:
    """Resolve *name* for *rdtype* and return a list of string rdata values."""
    resolver = _make_resolver(nameservers)
    try:
        answer = resolver.resolve(name, rdtype, raise_on_no_answer=False)
        if answer.rrset is None:
            return []
        return [r.to_text() for r in answer.rrset]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return []


def get_authoritative_ns(domain: str) -> list[str]:
    """Return IP addresses of the authoritative name servers for *domain*."""
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
    """Return PTR record for *ip* or empty string."""
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
    """Resolve A + AAAA records for *name*."""
    ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        ips.extend(resolve(name, rdtype))
    return ips
