"""BIMI (Brand Indicators for Message Identification) record lookup and validation.

BIMI allows domain owners to publish a verified brand logo that email clients
display next to authenticated messages.  Records are published as TXT records
at ``default._bimi.<domain>``.

References:

- BIMI Group specification: https://bimigroup.org/specification/
- RFC draft: https://datatracker.ietf.org/doc/html/draft-brand-indicators-for-message-identification
"""

from __future__ import annotations

import re

from mailvalidator.dns_utils import resolve
from mailvalidator.models import BIMIResult, CheckResult, Status


def check_bimi(domain: str) -> BIMIResult:
    """Look up and validate the BIMI record at ``default._bimi.<domain>``.

    :param domain: The domain whose BIMI record should be validated.
    :returns: A :class:`~mailvalidator.models.BIMIResult` containing the raw
        record string and :class:`~mailvalidator.models.CheckResult` items
        covering version, logo URL, and authority evidence.
    :rtype: ~mailvalidator.models.BIMIResult
    """
    result = BIMIResult(domain=domain)
    bimi_name = f"default._bimi.{domain}"

    records = resolve(bimi_name, "TXT")
    bimi_records = [r.strip('"') for r in records if "v=BIMI1" in r]

    if not bimi_records:
        result.checks.append(
            CheckResult(
                name="BIMI Record",
                status=Status.NOT_FOUND,
                details=[f"No BIMI record found at {bimi_name}."],
            )
        )
        return result

    record = bimi_records[0]
    result.record = record
    result.checks.append(
        CheckResult(name="BIMI Record", status=Status.OK, details=[record])
    )

    _validate(_parse_tags(record), result)
    return result


def _parse_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited ``tag=value`` pairs from a BIMI record string.

    :param record: Raw BIMI TXT record string.
    :returns: Mapping of tag names to their string values.
    :rtype: dict[str, str]
    """
    tags: dict[str, str] = {}
    for part in re.split(r"\s*;\s*", record):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    return tags


def _validate(tags: dict[str, str], result: BIMIResult) -> None:
    """Validate BIMI tag values and append :class:`~mailvalidator.models.CheckResult` items to *result*.

    :param tags: Parsed tag/value pairs from the BIMI record.
    :param result: Result object to append check items to.
    """
    # --- Version (v=) ---
    v = tags.get("v", "")
    if v != "BIMI1":
        result.checks.append(
            CheckResult(name="Version", status=Status.ERROR, value=v or "(missing)")
        )
    else:
        result.checks.append(
            CheckResult(name="Version", status=Status.OK, value="BIMI1")
        )

    # --- Logo URL (l=) ---
    l_tag = tags.get("l", "")
    if not l_tag:
        result.checks.append(
            CheckResult(
                name="Logo URL (l=)",
                status=Status.WARNING,
                details=["No l= logo URL specified."],
            )
        )
    elif not l_tag.startswith("https://"):
        result.checks.append(
            CheckResult(
                name="Logo URL (l=)",
                status=Status.ERROR,
                value=l_tag,
                details=["Logo URL must use HTTPS."],
            )
        )
    else:
        ext_ok = l_tag.lower().endswith(".svg") or l_tag.lower().endswith(".svg.gz")
        result.checks.append(
            CheckResult(
                name="Logo URL (l=)",
                status=Status.OK if ext_ok else Status.WARNING,
                value=l_tag,
                details=[] if ext_ok else ["Logo should be an SVG file per BIMI spec."],
            )
        )

    # --- Authority evidence (a=) ---
    # A Verified Mark Certificate (VMC) is required by major mailbox providers
    # such as Gmail and Apple Mail to actually display the logo.
    a_tag = tags.get("a", "")
    if a_tag:
        result.checks.append(
            CheckResult(name="Authority Evidence (a=)", status=Status.INFO, value=a_tag)
        )
    else:
        result.checks.append(
            CheckResult(
                name="Authority Evidence (a=)",
                status=Status.INFO,
                details=[
                    "No a= tag. A VMC certificate is required by some mailbox providers "
                    "(e.g. Gmail) to display the logo.",
                ],
            )
        )
