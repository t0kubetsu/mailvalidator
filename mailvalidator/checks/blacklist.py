"""DNS Blacklist / Blocklist (DNSBL / RBL) check.

Checks a single IP address against 100+ widely-used DNSBL zones in
parallel using a :class:`~concurrent.futures.ThreadPoolExecutor`.

Each zone is queried by reversing the IP octets and appending the zone
name (standard DNSBL protocol, RFC 5782).  A positive listing is
confirmed only when the query resolves to ``127.0.0.2``, which is the
RFC 5782 §2.1 standard "listed" response for IPv4 DNSBLs.  Other values
in the ``127.0.0.0/8`` range are intentionally ignored: some zones
(e.g. ``query.bondedsender.org``) resolve every query and return codes
such as ``127.255.255.255`` to convey metadata, not a blacklist verdict.
Accepting any resolution would produce false positives for those zones.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from mailvalidator.models import BlacklistResult, CheckResult, Status

# 100+ widely-used DNSBLs
DNSBL_ZONES: list[str] = [
    "0spam.fusionzero.com",
    "access.redhawk.org",
    "all.s5h.net",
    "b.barracudacentral.org",
    "bl.0spam.org",
    "bl.blocklist.de",
    "bl.emailbasura.org",
    "bl.mailspike.net",
    "bl.spamcop.net",
    "bl.spameatingmonkey.net",
    "black.uribl.com",
    "bogons.cymru.com",
    "cbl.abuseat.org",
    "combined.njabl.org",
    "csi.cloudmark.com",
    "db.wpbl.info",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.anticaptcha.net",
    "dnsbl.cyberlogic.net",
    "dnsbl.dronebl.org",
    "dnsbl.inps.de",
    "dnsbl.justspam.org",
    "dnsbl.kempt.net",
    "dnsbl.rv-soft.info",
    "dnsbl.sorbs.net",
    "dnsbl.spfbl.net",
    "dnsblchile.org",
    "dnsrbl.swinog.ch",
    "drone.abuse.ch",
    "dul.dnsbl.sorbs.net",
    "dul.ru",
    "escalations.dnsbl.sorbs.net",
    "fnrbl.fast.net",
    "grey.uribl.com",
    "hil.habeas.com",
    "http.dnsbl.sorbs.net",
    "httpbl.abuse.ch",
    "ips.backscatterer.org",
    "isps.severity.spamops.net",
    "ix.dnsbl.manitu.net",
    "l1.bbfh.ext.sorbs.net",
    "l2.bbfh.ext.sorbs.net",
    "l3.bbfh.ext.sorbs.net",
    "l4.bbfh.ext.sorbs.net",
    "mail-abuse.blacklist.jippg.org",
    "misc.dnsbl.sorbs.net",
    "msrbl.com",
    "multi.surbl.org",
    "multi.uribl.com",
    "netblock.pedantic.org",
    "netscan.rbl.blockedservers.com",
    "new.spam.dnsbl.sorbs.net",
    "no-more-funn.moensted.dk",
    "noptr.spamrats.com",
    "old.spam.dnsbl.sorbs.net",
    "orvedb.aupads.org",
    "pbl.spamhaus.org",
    "psbl.surriel.com",
    "query.bondedsender.org",
    "rbl.abuse.ro",
    "rbl.blockedservers.com",
    "rbl.dns-servicios.com",
    "rbl.efnetrbl.org",
    "rbl.interserver.net",
    "rbl.iprange.net",
    "rbl.megarbl.net",
    "rbl.rbldns.ru",
    "rbl.schulte.org",
    "recent.spam.dnsbl.sorbs.net",
    "red.uribl.com",
    "rep.mailfilter.com",
    "rot.blackspam.com",
    "sbl-xbl.spamhaus.org",
    "sbl.spamhaus.org",
    "short.rbl.jp",
    "singular.ttk.pte.hu",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.abuse.ch",
    "spam.dnsbl.sorbs.net",
    "spam.pedantic.org",
    "spam.rbl.blockedservers.com",
    "spambot.bls.digibase.ca",
    "spamguard.leadmon.net",
    "spamlist.or.kr",
    "spamrbl.imp.ch",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "spamsources.fabel.dk",
    "spamtrap.drbl.drand.net",
    "tor.dnsbl.sectoor.de",
    "torserver.tor.dnsbl.sectoor.de",
    "truncate.gbudb.net",
    "ubl.lashback.com",
    "ubl.unsubscore.com",
    "ubl.unsubscore.com",
    "virbl.dnsbl.bit.nl",
    "virbl.dnsbl.bit.nl",
    "vote.drbl.drand.net",
    "vote.drbl.gremlin.ru",
    "web.dnsbl.sorbs.net",
    "work.drbl.gremlin.ru",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.spamhaus.org",
    "zen.spamhaus.org",
]


def _reverse_ip(ip: str) -> str:
    """Reverse an IP address for use as a DNSBL query prefix.

    - IPv4: ``"1.2.3.4"`` → ``"4.3.2.1"``
    - IPv6: expanded nibble-reversed form per RFC 5782.

    :param ip: IPv4 or IPv6 address string.
    :returns: Reversed address string, or ``""`` if *ip* is not valid.
    :rtype: str
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return ".".join(reversed(ip.split(".")))
        # IPv6: expand, remove colons, reverse nibbles
        expanded = addr.exploded.replace(":", "")
        return ".".join(reversed(list(expanded)))
    except ValueError:
        return ""


def _check_single(ip: str, zone: str) -> tuple[str, bool]:
    """Query one DNSBL *zone* for *ip* and return ``(zone, listed)``.

    The DNSBL protocol works by looking up ``<reversed-ip>.<zone>`` as an A
    record.  A successful resolution means the IP is listed; NXDOMAIN means
    it is not.

    **Why ``127.0.0.2`` specifically**: RFC 5782 §2.1 defines ``127.0.0.2``
    as the standard "listed" response for IPv4 DNSBLs.  Some zones extend
    this with other values in the ``127.0.0.0/8`` range to encode listing
    reasons (e.g. ``127.0.0.3`` for spam source, ``127.0.0.4`` for open
    relay).  However, certain *allowlist* or *reputation* zones (such as
    ``query.bondedsender.org``) resolve queries for *any* submitted IP and
    return codes like ``127.255.255.255`` to convey metadata rather than a
    blacklisting verdict.  Accepting any resolution as a positive listing
    would therefore produce false positives for IPs that are not actually
    blacklisted.

    Restricting to ``127.0.0.2`` targets only the standard "listed" response
    and avoids misinterpreting informational or allowlist return codes.

    :param ip: IPv4 or IPv6 address to check.
    :type ip: str
    :param zone: DNSBL zone hostname (e.g. ``"zen.spamhaus.org"``).
    :type zone: str
    :returns: Tuple of ``(zone, is_listed)`` where *is_listed* is ``True``
        only when the query resolves to ``127.0.0.2``.
    :rtype: tuple[str, bool]
    """
    reversed_ip = _reverse_ip(ip)
    if not reversed_ip:
        return zone, False
    query = f"{reversed_ip}.{zone}"
    try:
        resolved_ip = socket.gethostbyname(query)
        return zone, resolved_ip == "127.0.0.2"
    except socket.gaierror:
        return zone, False


def check_blacklist(
    ip: str,
    zones: list[str] | None = None,
    max_workers: int = 50,
) -> BlacklistResult:
    """Check *ip* against DNS blacklist zones using parallel DNS queries.

    :param ip: IPv4 or IPv6 address to look up.
    :type ip: str
    :param zones: DNSBL zone list to query.  Defaults to the built-in
        :data:`DNSBL_ZONES` list (100+ zones).  Duplicates are removed
        automatically.
    :type zones: list[str] or None
    :param max_workers: Maximum number of concurrent DNS threads.
        Defaults to ``50``.
    :type max_workers: int
    :returns: Result containing the list of zones where *ip* was found
        listed and a single summary :class:`~mailvalidator.models.CheckResult`.
    :rtype: BlacklistResult
    """
    all_zones = zones or DNSBL_ZONES
    # deduplicate
    all_zones = list(dict.fromkeys(all_zones))

    result = BlacklistResult(ip=ip, total_checked=len(all_zones))
    listed_on: list[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_single, ip, z): z for z in all_zones}
        for future in as_completed(futures):
            zone, listed = future.result()
            if listed:
                listed_on.append(zone)

    result.listed_on = sorted(listed_on)

    if listed_on:
        result.checks.append(
            CheckResult(
                name="Blacklist Status",
                status=Status.ERROR,
                value=f"Listed on {len(listed_on)}/{len(all_zones)} blacklists",
                details=listed_on,
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name="Blacklist Status",
                status=Status.OK,
                value=f"Clean ({len(all_zones)} lists checked)",
                details=["IP is not listed on any checked DNSBL."],
            )
        )

    return result
