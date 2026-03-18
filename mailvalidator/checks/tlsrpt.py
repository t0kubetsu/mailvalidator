"""SMTP TLS Reporting (TLSRPT) record lookup and validation (RFC 8460).

TLSRPT allows receiving domains to publish a reporting endpoint where
sending MTAs can submit JSON reports about TLS negotiation failures.
The record is a TXT record at ``_smtp._tls.<domain>``.
"""

from __future__ import annotations

import re

from mailvalidator.dns_utils import resolve
from mailvalidator.models import CheckResult, Status, TLSRPTResult


def check_tlsrpt(domain: str) -> TLSRPTResult:
    """Look up and validate the TLSRPT record at ``_smtp._tls.<domain>``.

    :param domain: The domain whose TLSRPT record should be validated.
    :type domain: str
    :returns: Result containing the raw record and
        :class:`~mailvalidator.models.CheckResult` items for the version tag
        and each reporting URI in the ``rua=`` tag.
    :rtype: TLSRPTResult
    """
    result = TLSRPTResult(domain=domain)
    tlsrpt_name = f"_smtp._tls.{domain}"

    records = resolve(tlsrpt_name, "TXT")
    tls_records = [r.strip('"') for r in records if "v=TLSRPTv1" in r]

    if not tls_records:
        result.checks.append(
            CheckResult(
                name="TLSRPT Record",
                status=Status.NOT_FOUND,
                details=[
                    f"No TLSRPT record found at {tlsrpt_name}. SMTP TLS Reporting is not configured."
                ],
            )
        )
        return result

    record = tls_records[0]
    result.record = record
    result.checks.append(
        CheckResult(name="TLSRPT Record", status=Status.OK, details=[record])
    )

    tags = _parse_tags(record)
    _validate(tags, result)
    return result


def _parse_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited ``tag=value`` pairs from a TLSRPT record string.

    :param record: Raw TLSRPT TXT record value.
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


def _validate(tags: dict[str, str], result: TLSRPTResult) -> None:
    """Validate TLSRPT tag values and append :class:`~mailvalidator.models.CheckResult` items to *result*.

    :param tags: Parsed TLSRPT tag dictionary from :func:`_parse_tags`.
    :type tags: dict[str, str]
    :param result: Result object to which check items are appended.
    :type result: TLSRPTResult
    """
    v = tags.get("v", "")
    if v != "TLSRPTv1":
        result.checks.append(
            CheckResult(name="Version", status=Status.ERROR, value=v or "(missing)")
        )
    else:
        result.checks.append(
            CheckResult(name="Version", status=Status.OK, value="TLSRPTv1")
        )

    rua = tags.get("rua", "")
    if not rua:
        result.checks.append(
            CheckResult(
                name="Reporting URI (rua=)",
                status=Status.ERROR,
                details=["rua= is required by RFC 8460."],
            )
        )
        return

    uris = [u.strip() for u in rua.split(",")]
    for uri in uris:
        if uri.startswith("mailto:"):
            result.checks.append(
                CheckResult(name="Reporting URI", status=Status.OK, value=uri)
            )
        elif uri.startswith("https://"):
            result.checks.append(
                CheckResult(name="Reporting URI", status=Status.OK, value=uri)
            )
        else:
            result.checks.append(
                CheckResult(
                    name="Reporting URI",
                    status=Status.WARNING,
                    value=uri,
                    details=["URI should be mailto: or https:// per RFC 8460."],
                )
            )
