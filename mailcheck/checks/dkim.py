"""DKIM record lookup and validation."""

from __future__ import annotations

import re

from mailcheck.dns_utils import resolve
from mailcheck.models import CheckResult, DKIMResult, Status

# Required DKIM tags
_REQUIRED_TAGS = {"p"}  # public key
_VALID_VERSION = "DKIM1"


def check_dkim(domain: str, selector: str = "default") -> DKIMResult:
    """Look up and validate the DKIM TXT record at <selector>._domainkey.<domain>."""
    result = DKIMResult(domain=domain, selector=selector)
    dkim_name = f"{selector}._domainkey.{domain}"

    records = resolve(dkim_name, "TXT")
    dkim_records = [r.strip('"') for r in records if "v=DKIM1" in r or "p=" in r]

    if not dkim_records:
        result.checks.append(
            CheckResult(
                name="DKIM Record",
                status=Status.NOT_FOUND,
                details=[f"No DKIM record found at {dkim_name}"],
            )
        )
        return result

    record = " ".join(dkim_records)
    result.record = record

    result.checks.append(
        CheckResult(
            name="DKIM Record", status=Status.OK, value=dkim_name, details=[record]
        )
    )

    tags = _parse_tags(record)

    # version check
    v = tags.get("v", "")
    if v and v != _VALID_VERSION:
        result.checks.append(
            CheckResult(
                name="Version Tag",
                status=Status.WARNING,
                details=[f"v= is '{v}', expected 'DKIM1'."],
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name="Version Tag", status=Status.OK, value=v or "DKIM1 (implied)"
            )
        )

    # public key presence
    p = tags.get("p", "")
    if not p:
        result.checks.append(
            CheckResult(
                name="Public Key",
                status=Status.ERROR,
                details=["p= tag is missing or empty – key is revoked/invalid."],
            )
        )
    elif p == "":
        result.checks.append(
            CheckResult(
                name="Public Key",
                status=Status.WARNING,
                details=["p= is empty, meaning the key has been revoked."],
            )
        )
    else:
        result.checks.append(
            CheckResult(name="Public Key", status=Status.OK, value=f"{len(p)} chars")
        )

    # key type
    k = tags.get("k", "rsa")
    result.checks.append(CheckResult(name="Key Type", status=Status.INFO, value=k))

    # hash algorithms
    h = tags.get("h", "")
    if h and "sha1" in h.lower() and "sha256" not in h.lower():
        result.checks.append(
            CheckResult(
                name="Hash Algorithm",
                status=Status.WARNING,
                details=["Only SHA-1 listed; SHA-256 is recommended."],
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name="Hash Algorithm", status=Status.OK, value=h or "any (default)"
            )
        )

    return result


def _parse_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited tag=value pairs from a DKIM record string."""
    tags: dict[str, str] = {}
    for part in re.split(r"\s*;\s*", record):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    return tags
