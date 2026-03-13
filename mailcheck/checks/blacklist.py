"""DNS Blacklist / Blocklist (DNSBL / RBL) check."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from mailcheck.models import BlacklistResult, CheckResult, Status

# 100+ widely-used DNSBLs
DNSBL_ZONES: list[str] = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "dul.dnsbl.sorbs.net",
    "http.dnsbl.sorbs.net",
    "misc.dnsbl.sorbs.net",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "web.dnsbl.sorbs.net",
    "new.spam.dnsbl.sorbs.net",
    "recent.spam.dnsbl.sorbs.net",
    "old.spam.dnsbl.sorbs.net",
    "escalations.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "pbl.spamhaus.org",
    "sbl.spamhaus.org",
    "xbl.spamhaus.org",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "db.wpbl.info",
    "bl.blocklist.de",
    "all.s5h.net",
    "dnsrbl.swinog.ch",
    "ubl.unsubscore.com",
    "0spam.fusionzero.com",
    "spamrbl.imp.ch",
    "wormrbl.imp.ch",
    "virbl.dnsbl.bit.nl",
    "dnsbl.cyberlogic.net",
    "dnsbl.dronebl.org",
    "drone.abuse.ch",
    "httpbl.abuse.ch",
    "dul.ru",
    "dnsbl.inps.de",
    "ix.dnsbl.manitu.net",
    "combined.njabl.org",
    "no-more-funn.moensted.dk",
    "psbl.surriel.com",
    "spam.abuse.ch",
    "spamsources.fabel.dk",
    "bl.emailbasura.org",
    "rbl.schulte.org",
    "rbl.interserver.net",
    "access.redhawk.org",
    "bogons.cymru.com",
    "csi.cloudmark.com",
    "dnsbl.anticaptcha.net",
    "dnsbl.rv-soft.info",
    "dnsblchile.org",
    "fnrbl.fast.net",
    "hil.habeas.com",
    "isps.severity.spamops.net",
    "l1.bbfh.ext.sorbs.net",
    "l2.bbfh.ext.sorbs.net",
    "l3.bbfh.ext.sorbs.net",
    "l4.bbfh.ext.sorbs.net",
    "mail-abuse.blacklist.jippg.org",
    "msrbl.com",
    "netblock.pedantic.org",
    "netscan.rbl.blockedservers.com",
    "noptr.spamrats.com",
    "orvedb.aupads.org",
    "query.bondedsender.org",
    "rbl.abuse.ro",
    "rbl.blockedservers.com",
    "rbl.dns-servicios.com",
    "rbl.efnetrbl.org",
    "rbl.iprange.net",
    "rbl.megarbl.net",
    "rbl.rbldns.ru",
    "rep.mailfilter.com",
    "rot.blackspam.com",
    "sbl-xbl.spamhaus.org",
    "short.rbl.jp",
    "singular.ttk.pte.hu",
    "spam.pedantic.org",
    "spam.rbl.blockedservers.com",
    "spambot.bls.digibase.ca",
    "spamguard.leadmon.net",
    "spamlist.or.kr",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "spamtrap.drbl.drand.net",
    "tor.dnsbl.sectoor.de",
    "torserver.tor.dnsbl.sectoor.de",
    "truncate.gbudb.net",
    "ubl.lashback.com",
    "ubl.unsubscore.com",
    "virbl.dnsbl.bit.nl",
    "vote.drbl.drand.net",
    "vote.drbl.gremlin.ru",
    "work.drbl.gremlin.ru",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.spamhaus.org",
    "dnsbl.spfbl.net",
    "bl.0spam.org",
    "multi.uribl.com",
    "black.uribl.com",
    "grey.uribl.com",
    "red.uribl.com",
    "multi.surbl.org",
    "dnsbl.justspam.org",
    "dnsbl.kempt.net",
]


def _reverse_ip(ip: str) -> str:
    """Return dotted-decimal reversed IP for DNSBL query."""
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
    reversed_ip = _reverse_ip(ip)
    if not reversed_ip:
        return zone, False
    query = f"{reversed_ip}.{zone}"
    try:
        socket.gethostbyname(query)
        return zone, True
    except socket.gaierror:
        return zone, False


def check_blacklist(
    ip: str, zones: list[str] | None = None, max_workers: int = 50
) -> BlacklistResult:
    """Check *ip* against DNSBL zones (parallelised)."""
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
