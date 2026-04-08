"""MTA-STS DNS record and policy file validation (RFC 8461).

MTA-STS lets domain owners publish a policy that instructs sending MTAs
to always use TLS when delivering mail to the domain.  Two components
are checked:

1. The DNS TXT record at ``_mta-sts.<domain>`` (version + id tags).
2. The HTTPS policy file at ``https://mta-sts.<domain>/.well-known/mta-sts.txt``
   (mode, max_age, and mx entries).
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from mailvalidator.dns_utils import resolve
from mailvalidator.models import CheckResult, MTASTSResult, Status

_POLICY_URL_TPL = "https://mta-sts.{domain}/.well-known/mta-sts.txt"
_TIMEOUT = 10

# RFC 8461 §3.1 — id= must be 1–32 alphanumeric characters.
_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")

# RFC 8461 §3.1 — v=STSv1 must be the first tag.
_FIRST_TAG_RE = re.compile(r"^\s*v\s*=\s*STSv1", re.IGNORECASE)

# RFC 8461 §3.2 — recommended max_age ceiling (~1 year).
_MAX_AGE_CEILING = 31_557_600

# RFC 8461 §3.2 — valid MX pattern: bare hostname or *. wildcard prefix.
_MX_PATTERN_RE = re.compile(
    r"^(\*\.)?[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)


def check_mta_sts(domain: str) -> MTASTSResult:
    """Check the MTA-STS DNS record and policy file for *domain*.

    Performs two checks:

    1. Looks up the TXT record at ``_mta-sts.<domain>`` and validates the
       ``v=`` version tag and the required ``id=`` field.
    2. Fetches the HTTPS policy file at
       ``https://mta-sts.<domain>/.well-known/mta-sts.txt`` and validates
       the ``mode``, ``max_age``, and ``mx`` entries.

    :param domain: Domain whose MTA-STS configuration should be validated.
    :type domain: str
    :returns: A :class:`~mailvalidator.models.MTASTSResult` containing the raw
        DNS record, the parsed policy dict, and a list of
        :class:`~mailvalidator.models.CheckResult` items for each validated field.
    :rtype: ~mailvalidator.models.MTASTSResult
    """
    result = MTASTSResult(domain=domain)

    # --- DNS TXT record ---
    sts_name = f"_mta-sts.{domain}"
    records = resolve(sts_name, "TXT")
    sts_records = [r.strip('"') for r in records if "v=STSv1" in r]

    if not sts_records:
        result.checks.append(
            CheckResult(
                name="MTA-STS DNS Record",
                status=Status.NOT_FOUND,
                details=[f"No MTA-STS TXT record found at {sts_name}."],
            )
        )
        return result

    # M1: Multiple matching DNS records are undefined behaviour (RFC 8461 §3.1).
    if len(sts_records) > 1:
        result.checks.append(
            CheckResult(
                name="MTA-STS DNS Record",
                status=Status.ERROR,
                details=[
                    f"Multiple MTA-STS TXT records found at {sts_name}. "
                    "RFC 8461 §3.1 requires exactly one; remove all but one.",
                ],
            )
        )
        return result

    dns_record = sts_records[0]
    result.dns_record = dns_record
    result.checks.append(
        CheckResult(name="MTA-STS DNS Record", status=Status.OK, details=[dns_record])
    )

    dns_tags = _parse_dns_record(dns_record)

    # M9: v=STSv1 must be the first tag (RFC 8461 §3.1).
    if dns_tags.get("v") != "STSv1":
        result.checks.append(
            CheckResult(
                name="DNS Version",
                status=Status.ERROR,
                value=dns_tags.get("v", "(missing)"),
            )
        )
    elif not _FIRST_TAG_RE.match(dns_record):
        result.checks.append(
            CheckResult(
                name="DNS Version",
                status=Status.WARNING,
                value="STSv1",
                details=[
                    "v=STSv1 is not the first tag in the DNS record. "
                    "RFC 8461 §3.1 requires v= to appear first."
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(name="DNS Version", status=Status.OK, value="STSv1")
        )

    # id= (must exist and match RFC 8461 §3.1 format: 1–32 alphanumeric chars)
    sts_id = dns_tags.get("id", "")
    if not sts_id:
        result.checks.append(
            CheckResult(
                name="Record ID (id=)",
                status=Status.ERROR,
                details=["id= is required."],
            )
        )
    elif not _ID_RE.match(sts_id):
        # M2: id= must be 1–32 alphanumeric characters (RFC 8461 §3.1).
        result.checks.append(
            CheckResult(
                name="Record ID (id=)",
                status=Status.ERROR,
                value=sts_id,
                details=[
                    "id= must be 1–32 alphanumeric characters per RFC 8461 §3.1. "
                    f"Got: {sts_id!r}"
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(name="Record ID (id=)", status=Status.OK, value=sts_id)
        )

    # --- fetch policy file ---
    policy_url = _POLICY_URL_TPL.format(domain=domain)
    policy_text, content_type, fetch_error = _fetch_policy(policy_url)

    if fetch_error:
        result.checks.append(
            CheckResult(
                name="Policy File",
                status=Status.ERROR,
                details=[f"Could not fetch policy from {policy_url}: {fetch_error}"],
            )
        )
        return result

    result.checks.append(
        CheckResult(name="Policy File", status=Status.OK, value=policy_url)
    )

    # M3: Server must respond with Content-Type: text/plain (RFC 8461 §3.2).
    if content_type and not content_type.startswith("text/plain"):
        result.checks.append(
            CheckResult(
                name="Policy File Content-Type",
                status=Status.WARNING,
                value=content_type,
                details=[
                    f"RFC 8461 §3.2 requires Content-Type: text/plain; got {content_type!r}."
                ],
            )
        )

    policy = _parse_policy_file(policy_text)
    result.policy = {
        k: ", ".join(v) if isinstance(v, list) else v for k, v in policy.items()
    }
    _validate_policy(policy, policy_text, result)
    return result


def _parse_dns_record(record: str) -> dict[str, str]:
    """Parse a DNS TXT record with semicolon-delimited ``tag=value`` pairs.

    Example input: ``v=STSv1; id=20240101T000000``

    :param record: Raw MTA-STS DNS TXT record value.
    :type record: str
    :returns: Mapping of tag names to their string values.
    :rtype: dict[str, str]
    """
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    return tags


def _parse_policy_file(text: str) -> dict[str, str | list[str]]:
    """Parse an MTA-STS policy file with ``key: value`` lines (one per line).

    The ``mx`` key may appear multiple times and is collected into a list.
    All other keys are single-valued strings.

    Example policy file::

        version: STSv1
        mode: enforce
        max_age: 604800
        mx: mail.example.com
        mx: *.example.com

    :param text: Raw text content of the policy file.
    :type text: str
    :returns: Parsed policy mapping; ``mx`` values are returned as a list,
        all other values as strings.
    :rtype: dict[str, str or list[str]]
    """
    tags: dict[str, str | list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k == "mx":
            existing = tags.get("mx", [])
            if isinstance(existing, list):
                existing.append(v)
            else:
                existing = [existing, v]  # pragma: no cover
            tags["mx"] = existing
        else:
            tags[k] = v
    return tags


def _fetch_policy(url: str) -> tuple[str, str, str]:
    """Fetch the MTA-STS policy file from *url* over HTTPS.

    :param url: Full HTTPS URL of the policy file.
    :type url: str
    :returns: ``(policy_text, content_type, "")`` on success, or
        ``("", "", error_message)`` on any network or HTTP error.
    :rtype: tuple[str, str, str]
    """
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:  # noqa: S310
            content_type = resp.headers.get("Content-Type", "")
            return resp.read().decode(errors="replace"), content_type, ""
    except urllib.error.URLError as exc:
        return "", "", str(exc)
    except Exception as exc:  # noqa: BLE001
        return "", "", str(exc)


def _validate_policy(
    policy: dict[str, str | list[str]],
    raw_text: str,
    result: MTASTSResult,
) -> None:
    """Validate MTA-STS policy file fields and append :class:`~mailvalidator.models.CheckResult` items to *result*.

    :param policy: Parsed policy dict from :func:`_parse_policy_file`.
    :type policy: dict[str, str or list[str]]
    :param raw_text: Raw policy file text (used for ordering and line-ending checks).
    :type raw_text: str
    :param result: Result object to which check items are appended.
    :type result: ~mailvalidator.models.MTASTSResult
    """
    # M4: policy file must begin with version: STSv1 (RFC 8461 §3.2).
    version_field = policy.get("version", "")
    if str(version_field) != "STSv1":
        result.checks.append(
            CheckResult(
                name="Policy Version",
                status=Status.ERROR,
                value=str(version_field) if version_field else "(missing)",
                details=[
                    "The policy file must contain 'version: STSv1' per RFC 8461 §3.2."
                ],
            )
        )
    else:
        # Also check it is the first non-empty field in the file.
        first_key = next(
            (
                line.split(":", 1)[0].strip()
                for line in raw_text.splitlines()
                if ":" in line and line.strip()
            ),
            None,
        )
        if first_key and first_key != "version":
            result.checks.append(
                CheckResult(
                    name="Policy Version",
                    status=Status.WARNING,
                    value="STSv1",
                    details=[
                        "version: STSv1 is present but is not the first field. "
                        "RFC 8461 §3.2 requires it to appear first."
                    ],
                )
            )
        else:
            result.checks.append(
                CheckResult(name="Policy Version", status=Status.OK, value="STSv1")
            )

    # M8: RFC 8461 §3.2 requires CRLF line endings. Note if LF-only is detected.
    if "\r\n" not in raw_text and "\n" in raw_text:
        result.checks.append(
            CheckResult(
                name="Policy File Line Endings",
                status=Status.WARNING,
                details=[
                    "Policy file uses LF-only line endings. "
                    "RFC 8461 §3.2 requires CRLF (\\r\\n) line termination."
                ],
            )
        )

    # mode
    mode = policy.get("mode", "")
    mode_status = {
        "enforce": Status.OK,
        "testing": Status.WARNING,
        "none": Status.WARNING,
    }
    result.checks.append(
        CheckResult(
            name="Policy Mode",
            status=mode_status.get(str(mode), Status.ERROR),
            value=str(mode) if mode else "(missing)",
            details=(
                ["Mode 'testing' means the policy is not yet enforced."]
                if mode == "testing"
                else ["Mode 'none' effectively disables MTA-STS."]
                if mode == "none"
                else []
            ),
        )
    )

    # max_age
    max_age = policy.get("max_age", "")
    if max_age:
        try:
            age_int = int(str(max_age))
            if age_int < 86400:
                result.checks.append(
                    CheckResult(
                        name="max_age",
                        status=Status.WARNING,
                        value=str(age_int),
                        details=["max_age under 86400 s (1 day) is very short."],
                    )
                )
            elif age_int > _MAX_AGE_CEILING:
                # M5: RFC 8461 §3.2 recommends a maximum of ~1 year.
                result.checks.append(
                    CheckResult(
                        name="max_age",
                        status=Status.WARNING,
                        value=f"{age_int} s",
                        details=[
                            f"max_age exceeds the recommended ceiling of {_MAX_AGE_CEILING} s (~1 year) "
                            "per RFC 8461 §3.2. Consider reducing it."
                        ],
                    )
                )
            else:
                result.checks.append(
                    CheckResult(
                        name="max_age",
                        status=Status.OK,
                        value=f"{age_int} s ({age_int // 86400} d)",
                    )
                )
        except ValueError:
            result.checks.append(
                CheckResult(name="max_age", status=Status.ERROR, value=str(max_age))
            )
    else:
        result.checks.append(
            CheckResult(
                name="max_age", status=Status.ERROR, details=["max_age is required."]
            )
        )

    # mx entries (now always a list)
    mx_entries = policy.get("mx", [])
    if isinstance(mx_entries, str):
        mx_entries = [mx_entries]
    if mx_entries:
        # M6: Validate that each entry is a valid hostname or wildcard pattern.
        invalid_mx: list[str] = [m for m in mx_entries if not _MX_PATTERN_RE.match(m)]
        if invalid_mx:
            result.checks.append(
                CheckResult(
                    name="MX Entries",
                    status=Status.WARNING,
                    value=", ".join(mx_entries),
                    details=[
                        f"Invalid MX pattern(s) per RFC 8461 §3.2: {', '.join(invalid_mx)}. "
                        "Each entry must be a valid hostname or a *.hostname wildcard."
                    ],
                )
            )
        else:
            # M7: Detect duplicate mx: entries (RFC 8461 §3.2 — each pattern should be distinct).
            seen_mx: set[str] = set()
            dup_mx: list[str] = []
            for m in mx_entries:
                if m in seen_mx:
                    dup_mx.append(m)
                seen_mx.add(m)
            if dup_mx:
                result.checks.append(
                    CheckResult(
                        name="MX Entries",
                        status=Status.WARNING,
                        value=", ".join(mx_entries),
                        details=[
                            f"Duplicate mx: entries found: {', '.join(sorted(set(dup_mx)))}. "
                            "Each MX pattern should appear at most once (RFC 8461 §3.2)."
                        ],
                    )
                )
            else:
                result.checks.append(
                    CheckResult(
                        name="MX Entries", status=Status.OK, value=", ".join(mx_entries)
                    )
                )
    else:
        result.checks.append(
            CheckResult(
                name="MX Entries",
                status=Status.WARNING,
                details=["No mx: entries found in policy file."],
            )
        )
