"""DMARC record lookup and validation (RFC 7489).

The DMARC policy record is published at ``_dmarc.<domain>`` and tells
receivers how to handle messages that fail SPF and DKIM alignment:

* ``p=none``       – take no action (monitoring only)
* ``p=quarantine`` – deliver to spam/junk folder
* ``p=reject``     – reject the message outright

This check also validates the aggregate reporting URI (``rua=``), the
forensic reporting URI (``ruf=``), alignment modes, and the percentage
tag (``pct=``).
"""

from __future__ import annotations

import re

from mailvalidator.dns_utils import resolve
from mailvalidator.models import CheckResult, DMARCResult, Status


def check_dmarc(domain: str) -> DMARCResult:
    """Look up and validate the DMARC record at ``_dmarc.<domain>``.

    :param domain: The domain whose DMARC record should be validated.
    :type domain: str
    :returns: Result containing the raw record and
        :class:`~mailvalidator.models.CheckResult` items for policy,
        subdomain policy, reporting URIs, alignment, and percentage.
    :rtype: DMARCResult
    """
    result = DMARCResult(domain=domain)
    dmarc_name = f"_dmarc.{domain}"

    records = resolve(dmarc_name, "TXT")
    dmarc_records = [r.strip('"') for r in records if "v=DMARC1" in r]

    if not dmarc_records:
        result.checks.append(
            CheckResult(
                name="DMARC Record",
                status=Status.NOT_FOUND,
                details=[f"No DMARC record found at {dmarc_name}."],
            )
        )
        return result

    if len(dmarc_records) > 1:
        result.checks.append(
            CheckResult(
                name="Multiple DMARC Records",
                status=Status.ERROR,
                details=["Only one DMARC record is allowed."],
            )
        )

    record = dmarc_records[0]
    result.record = record
    result.checks.append(
        CheckResult(name="DMARC Record", status=Status.OK, details=[record])
    )

    tags = _parse_tags(record)
    _validate(tags, result)
    return result


def _parse_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited ``tag=value`` pairs from a DMARC record string.

    :param record: Raw DMARC TXT record value.
    :type record: str
    :returns: Mapping of tag names to their string values.
    :rtype: dict[str, str]
    """
    tags: dict[str, str] = {}
    for part in re.split(r"\s*;\s*", record):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    return tags


def _validate(tags: dict[str, str], result: DMARCResult) -> None:
    """Validate DMARC tag values and append :class:`~mailvalidator.models.CheckResult` items to *result*.

    :param tags: Parsed DMARC tag dictionary from :func:`_parse_tags`.
    :type tags: dict[str, str]
    :param result: Result object to which check items are appended.
    :type result: DMARCResult
    """
    # policy (p=)
    policy = tags.get("p", "")
    policy_status = {
        "none": Status.WARNING,
        "quarantine": Status.OK,
        "reject": Status.OK,
    }
    if policy not in policy_status:
        result.checks.append(
            CheckResult(
                name="Policy (p=)",
                status=Status.ERROR,
                value=policy or "(missing)",
                details=["p= must be none, quarantine, or reject."],
            )
        )
    else:
        status = policy_status[policy]
        details = []
        if policy == "none":
            details = [
                "p=none means no action is taken. Upgrade to quarantine or reject."
            ]
        result.checks.append(
            CheckResult(
                name="Policy (p=)", status=status, value=policy, details=details
            )
        )

    # subdomain policy (sp=)
    sp = tags.get("sp", "")
    if sp:
        result.checks.append(
            CheckResult(name="Subdomain Policy (sp=)", status=Status.INFO, value=sp)
        )

    # pct=
    pct = tags.get("pct", "100")
    try:
        pct_int = int(pct)
        if pct_int < 100:
            result.checks.append(
                CheckResult(
                    name="Percentage (pct=)",
                    status=Status.WARNING,
                    value=f"{pct_int}%",
                    details=[
                        "pct < 100 means only a portion of messages are subject to DMARC policy."
                    ],
                )
            )
        else:
            result.checks.append(
                CheckResult(name="Percentage (pct=)", status=Status.OK, value="100%")
            )
    except ValueError:
        result.checks.append(
            CheckResult(name="Percentage (pct=)", status=Status.ERROR, value=pct)
        )

    # rua= reporting URI
    rua = tags.get("rua", "")
    if rua:
        result.checks.append(
            CheckResult(name="Aggregate Reports (rua=)", status=Status.OK, value=rua)
        )
    else:
        result.checks.append(
            CheckResult(
                name="Aggregate Reports (rua=)",
                status=Status.WARNING,
                details=["No rua= tag. You will not receive aggregate DMARC reports."],
            )
        )

    # ruf= forensic reporting URI
    ruf = tags.get("ruf", "")
    if ruf:
        result.checks.append(
            CheckResult(name="Forensic Reports (ruf=)", status=Status.INFO, value=ruf)
        )

    # alignment
    for tag, label in (("adkim", "DKIM Alignment"), ("aspf", "SPF Alignment")):
        val = tags.get(tag, "r")
        result.checks.append(
            CheckResult(
                name=label,
                status=Status.INFO,
                value="relaxed" if val == "r" else "strict",
            )
        )
