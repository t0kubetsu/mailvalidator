"""SPF record lookup and validation."""

from __future__ import annotations

import re

from mailcheck.dns_utils import resolve
from mailcheck.models import CheckResult, SPFResult, Status

_MAX_DNS_LOOKUPS = 10
_DNS_MECHANISMS = {"a", "mx", "include", "exists", "redirect"}


def check_spf(domain: str) -> SPFResult:
    result = SPFResult(domain=domain)

    records = resolve(domain, "TXT")
    spf_records = [r.strip('"') for r in records if r.strip('"').startswith("v=spf1")]

    if not spf_records:
        result.checks.append(
            CheckResult(
                name="SPF Record",
                status=Status.NOT_FOUND,
                details=[f"No SPF record found for {domain}."],
            )
        )
        return result

    if len(spf_records) > 1:
        result.checks.append(
            CheckResult(
                name="Multiple SPF Records",
                status=Status.ERROR,
                details=[
                    "More than one SPF record found. RFC 7208 requires exactly one SPF record."
                ],
            )
        )

    record = spf_records[0]
    result.record = record

    result.checks.append(
        CheckResult(name="SPF Record", status=Status.OK, details=[record])
    )

    _validate_spf(record, result)
    return result


def _validate_spf(record: str, result: SPFResult) -> None:
    terms = record.split()

    # version
    if terms[0] != "v=spf1":
        result.checks.append(
            CheckResult(name="SPF Version", status=Status.ERROR, value=terms[0])
        )
        return
    result.checks.append(
        CheckResult(name="SPF Version", status=Status.OK, value="v=spf1")
    )

    # all qualifier
    all_term = next((t for t in terms if re.match(r"[+\-~?]?all$", t)), None)
    if not all_term:
        result.checks.append(
            CheckResult(
                name="'all' Mechanism",
                status=Status.WARNING,
                details=["No 'all' term found; SPF is incomplete."],
            )
        )
    elif all_term.startswith("+"):
        result.checks.append(
            CheckResult(
                name="'all' Mechanism",
                status=Status.ERROR,
                value=all_term,
                details=[
                    "+all allows ANY server to send mail – this is a critical misconfiguration."
                ],
            )
        )
    elif all_term.startswith("~"):
        result.checks.append(
            CheckResult(
                name="'all' Mechanism",
                status=Status.WARNING,
                value=all_term,
                details=[
                    "~all (softfail) is permissive. Consider -all for stricter enforcement."
                ],
            )
        )
    elif all_term.startswith("?"):
        result.checks.append(
            CheckResult(
                name="'all' Mechanism",
                status=Status.WARNING,
                value=all_term,
                details=["?all (neutral) provides no protection."],
            )
        )
    else:
        result.checks.append(
            CheckResult(name="'all' Mechanism", status=Status.OK, value=all_term)
        )

    # count DNS-lookup mechanisms
    dns_count = sum(
        1
        for t in terms
        if any(
            t.lstrip("+-~?").startswith(m + ":") or t.lstrip("+-~?") == m
            for m in _DNS_MECHANISMS
        )
    )
    if dns_count > _MAX_DNS_LOOKUPS:
        result.checks.append(
            CheckResult(
                name="DNS Lookup Count",
                status=Status.ERROR,
                value=str(dns_count),
                details=[
                    f"Exceeds the {_MAX_DNS_LOOKUPS}-lookup limit (RFC 7208 §4.6.4). Some servers will fail SPF evaluation."
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name="DNS Lookup Count",
                status=Status.OK,
                value=f"{dns_count}/{_MAX_DNS_LOOKUPS}",
            )
        )

    # ptr deprecation
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        result.checks.append(
            CheckResult(
                name="ptr Mechanism",
                status=Status.WARNING,
                details=["Use of 'ptr' is deprecated (RFC 7208 §5.5). Remove it."],
            )
        )
