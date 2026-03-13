"""DKIM record lookup and validation."""

from __future__ import annotations

from mailcheck.dns_utils import resolve
from mailcheck.models import CheckResult, DKIMResult, Status


def check_dkim(domain: str) -> DKIMResult:
    """Validate DKIM support by checking the _domainkey.<domain> base node."""
    result = DKIMResult(domain=domain)

    # Check that _domainkey.<domain> exists as an empty non-terminal (RFC 2308).
    # A conformant name server must answer NOERROR even when no records exist at
    # that exact node, because child records (selectors) are present beneath it.
    # Non-conformant servers answer NXDOMAIN, which prevents DKIM discovery.
    base_domainkey = f"_domainkey.{domain}"
    base_status = resolve(base_domainkey, "TXT")  # None signals NXDOMAIN
    if base_status is None:
        result.checks.append(
            CheckResult(
                name="DKIM Base Node",
                status=Status.ERROR,
                details=[
                    f"{base_domainkey} returned NXDOMAIN. "
                    "Your name server is not RFC 2308-conformant: it must answer "
                    "NOERROR for an empty non-terminal node so receivers can detect "
                    "DKIM support without knowing the selector in advance."
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name="DKIM Base Node",
                status=Status.OK,
                value=base_domainkey,
                details=[f"{base_domainkey} answered NOERROR (RFC 2308-conformant)."],
            )
        )

    return result
