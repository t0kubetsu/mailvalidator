"""MX record lookup and basic validation.

Records are fetched from the domain's own authoritative name servers
(discovered via an NS query) so results are not subject to recursive-
resolver caching.  A fallback to the configured system resolver is used
when the authoritative servers cannot be reached.
"""

from __future__ import annotations


from mailvalidator.dns_utils import get_authoritative_ns, resolve, resolve_a
from mailvalidator.models import CheckResult, MXRecord, MXResult, Status


def check_mx(domain: str) -> MXResult:
    """Look up MX records via the domain's authoritative name servers.

    :param domain: The domain whose MX records should be queried.
    :type domain: str
    :returns: Result containing sorted MX records and diagnostic checks.
    :rtype: MXResult
    """
    result = MXResult(domain=domain)

    # --- discover authoritative name servers ---
    auth_ns = get_authoritative_ns(domain)
    result.authoritative_ns = auth_ns

    # --- fetch MX records (prefer authoritative, fall back to recursive) ---
    raw_mx = resolve(domain, "MX", nameservers=auth_ns if auth_ns else None)

    if not raw_mx:
        result.checks.append(
            CheckResult(
                name="MX Records",
                status=Status.NOT_FOUND,
                value="",
                details=["No MX records found for this domain."],
            )
        )
        return result

    records: list[MXRecord] = []
    for entry in raw_mx:
        # entry format: "<priority> <exchange>"
        parts = entry.split()
        if len(parts) != 2:
            continue
        priority = int(parts[0])
        exchange = parts[1].rstrip(".")
        ips = resolve_a(exchange)
        records.append(MXRecord(priority=priority, exchange=exchange, ip_addresses=ips))

    records.sort(key=lambda r: r.priority)
    result.records = records

    result.checks.append(
        CheckResult(
            name="MX Records",
            status=Status.OK,
            value=f"{len(records)} record(s) found",
            details=[
                f"Priority {r.priority}: {r.exchange} → {', '.join(r.ip_addresses) or 'no A/AAAA'}"
                for r in records
            ],
        )
    )

    # --- duplicate-priority warning ---
    priorities = [r.priority for r in records]
    if len(priorities) != len(set(priorities)):
        result.checks.append(
            CheckResult(
                name="Duplicate Priorities",
                status=Status.WARNING,
                details=["Multiple MX records share the same priority value."],
            )
        )

    return result
