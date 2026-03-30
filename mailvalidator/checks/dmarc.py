"""DMARC record lookup and validation (RFC 7489).

The DMARC policy record is published at ``_dmarc.<domain>`` and tells
receivers how to handle messages that fail SPF and DKIM alignment:

* ``p=none``       – take no action (monitoring only)
* ``p=quarantine`` – deliver to spam/junk folder
* ``p=reject``     – reject the message outright

Checks implemented
------------------
* Record presence and uniqueness (§3.1, §6.6)
* ``v=DMARC1`` is the **first** tag in the record (§6.3)
* ``p=`` policy value and grade (§6.3)
* ``sp=`` subdomain policy value (§6.3)
* ``pct=`` in range 0–100 (§6.4)
* ``adkim=`` and ``aspf=`` values are ``r`` or ``s`` (§6.4)
* ``fo=`` forensic reporting option values (§6.4)
* ``ri=`` reporting interval is a positive integer (§6.4)
* ``rua=`` and ``ruf=`` URI scheme validation (``mailto:`` / ``https:``) (§6.4)
* ``rua=`` and ``ruf=`` ``mailto:`` address syntax (§6.4, §10.1.2)
* ``rua=`` and ``ruf=`` external destination verification DNS lookup (§7.1)
"""

from __future__ import annotations

import re
import urllib.parse

from mailvalidator.dns_utils import resolve
from mailvalidator.models import CheckResult, DMARCResult, Status

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_POLICIES: frozenset[str] = frozenset({"none", "quarantine", "reject"})
_VALID_ALIGNMENT: frozenset[str] = frozenset({"r", "s"})
_VALID_FO_CHARS: frozenset[str] = frozenset({"0", "1", "d", "s"})
_VALID_URI_SCHEMES: frozenset[str] = frozenset({"mailto", "https"})

# Minimal RFC 5321 local-part + domain check; not a full parser but catches
# obvious malformations (no @, missing domain, etc.).
_MAILTO_RE = re.compile(
    r"^[^@\s]+@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_dmarc(domain: str) -> DMARCResult:
    """Look up and validate the DMARC record at ``_dmarc.<domain>``.

    Validates the record against RFC 7489 including external destination
    verification (§7.1) for ``rua=`` and ``ruf=`` URIs that point to a
    different organisational domain.

    :param domain: The domain whose DMARC record should be validated.
    :type domain: str
    :returns: Result containing the raw record and
        :class:`~mailvalidator.models.CheckResult` items for every validated tag.
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
                details=["Only one DMARC record is allowed (RFC 7489 §6.6)."],
            )
        )

    record = dmarc_records[0]
    result.record = record
    result.checks.append(
        CheckResult(name="DMARC Record", status=Status.OK, details=[record])
    )

    tags = _parse_tags(record)
    _validate(tags, domain, record, result)
    return result


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


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


def _first_tag(record: str) -> str:
    """Return the key of the first ``tag=value`` pair in *record*.

    :param record: Raw DMARC TXT record value.
    :type record: str
    :returns: The first tag name, e.g. ``\"v\"``.
    :rtype: str
    """
    for part in re.split(r"\s*;\s*", record):
        if "=" in part:
            return part.partition("=")[0].strip()
    return ""


# ---------------------------------------------------------------------------
# Validation orchestrator
# ---------------------------------------------------------------------------


def _validate(
    tags: dict[str, str],
    domain: str,
    record: str,
    result: DMARCResult,
) -> None:
    """Run all tag-level validations and append results to *result*.

    :param tags: Parsed DMARC tag dictionary.
    :type tags: dict[str, str]
    :param domain: The assessed domain (used for external URI verification).
    :type domain: str
    :param record: Raw record string (used to check tag ordering).
    :type record: str
    :param result: Result object to which check items are appended.
    :type result: DMARCResult
    """
    _check_version_first(record, result)
    _check_policy(tags, result)
    _check_subdomain_policy(tags, result)
    _check_pct(tags, result)
    _check_alignment(tags, result)
    _check_fo(tags, result)
    _check_ri(tags, result)
    _check_reporting_uris("rua", "Aggregate Reports (rua=)", domain, tags, result)
    _check_reporting_uris("ruf", "Forensic Reports (ruf=)", domain, tags, result)


# ---------------------------------------------------------------------------
# Individual tag checks
# ---------------------------------------------------------------------------


def _check_version_first(record: str, result: DMARCResult) -> None:
    """Verify that ``v=DMARC1`` is the first tag (RFC 7489 §6.3).

    :param record: Raw DMARC TXT record value.
    :param result: Result object to append to.
    """
    if _first_tag(record) != "v":
        result.checks.append(
            CheckResult(
                name="Tag Order (v=)",
                status=Status.ERROR,
                details=[
                    "v=DMARC1 MUST be the first tag in the record (RFC 7489 §6.3). "
                    "Records that do not start with v=DMARC1 are ignored by receivers."
                ],
            )
        )


def _check_policy(tags: dict[str, str], result: DMARCResult) -> None:
    """Validate the ``p=`` policy tag (RFC 7489 §6.3).

    :param tags: Parsed tag dictionary.
    :param result: Result object to append to.
    """
    policy = tags.get("p", "")
    if policy not in _VALID_POLICIES:
        result.checks.append(
            CheckResult(
                name="Policy (p=)",
                status=Status.ERROR,
                value=policy or "(missing)",
                details=["p= must be none, quarantine, or reject (RFC 7489 §6.3)."],
            )
        )
        return

    status = Status.WARNING if policy == "none" else Status.OK
    details = (
        [
            "p=none means no action is taken on failing messages. "
            "Use p=quarantine or p=reject once you have reviewed your reports."
        ]
        if policy == "none"
        else []
    )
    result.checks.append(
        CheckResult(name="Policy (p=)", status=status, value=policy, details=details)
    )


def _check_subdomain_policy(tags: dict[str, str], result: DMARCResult) -> None:
    """Validate the optional ``sp=`` subdomain policy tag (RFC 7489 §6.3).

    :param tags: Parsed tag dictionary.
    :param result: Result object to append to.
    """
    sp = tags.get("sp", "")
    if not sp:
        return
    if sp not in _VALID_POLICIES:
        result.checks.append(
            CheckResult(
                name="Subdomain Policy (sp=)",
                status=Status.ERROR,
                value=sp,
                details=["sp= must be none, quarantine, or reject (RFC 7489 §6.3)."],
            )
        )
    else:
        result.checks.append(
            CheckResult(name="Subdomain Policy (sp=)", status=Status.INFO, value=sp)
        )


def _check_pct(tags: dict[str, str], result: DMARCResult) -> None:
    """Validate the ``pct=`` percentage tag (RFC 7489 §6.4).

    Must be an integer in the range 0–100.

    :param tags: Parsed tag dictionary.
    :param result: Result object to append to.
    """
    pct = tags.get("pct", "100")
    try:
        pct_int = int(pct)
    except ValueError:
        result.checks.append(
            CheckResult(
                name="Percentage (pct=)",
                status=Status.ERROR,
                value=pct,
                details=["pct= must be an integer (RFC 7489 §6.4)."],
            )
        )
        return

    if not (0 <= pct_int <= 100):
        result.checks.append(
            CheckResult(
                name="Percentage (pct=)",
                status=Status.ERROR,
                value=str(pct_int),
                details=["pct= must be in the range 0–100 (RFC 7489 §6.4)."],
            )
        )
    elif pct_int < 100:
        result.checks.append(
            CheckResult(
                name="Percentage (pct=)",
                status=Status.WARNING,
                value=f"{pct_int}%",
                details=[
                    f"pct={pct_int} means only {pct_int}% of failing messages are "
                    "subject to the DMARC policy. Set pct=100 for full enforcement."
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(name="Percentage (pct=)", status=Status.OK, value="100%")
        )


def _check_alignment(tags: dict[str, str], result: DMARCResult) -> None:
    """Validate ``adkim=`` and ``aspf=`` alignment mode tags (RFC 7489 §6.4).

    Both must be ``r`` (relaxed, default) or ``s`` (strict).

    :param tags: Parsed tag dictionary.
    :param result: Result object to append to.
    """
    for tag, label in (
        ("adkim", "DKIM Alignment (adkim=)"),
        ("aspf", "SPF Alignment (aspf=)"),
    ):
        val = tags.get(tag, "r")
        if val not in _VALID_ALIGNMENT:
            result.checks.append(
                CheckResult(
                    name=label,
                    status=Status.ERROR,
                    value=val,
                    details=[
                        f"{tag}= must be 'r' (relaxed) or 's' (strict) (RFC 7489 §6.4)."
                    ],
                )
            )
        else:
            result.checks.append(
                CheckResult(
                    name=label,
                    status=Status.INFO,
                    value="relaxed" if val == "r" else "strict",
                )
            )


def _check_fo(tags: dict[str, str], result: DMARCResult) -> None:
    """Validate the ``fo=`` forensic reporting option tag (RFC 7489 §6.4).

    Valid values are colon-delimited combinations of ``0``, ``1``, ``d``, ``s``.

    * ``0`` – generate report if all mechanisms fail (default)
    * ``1`` – generate report if any mechanism fails
    * ``d`` – generate report on DKIM evaluation failure
    * ``s`` – generate report on SPF evaluation failure

    :param tags: Parsed tag dictionary.
    :param result: Result object to append to.
    """
    fo = tags.get("fo", "")
    if not fo:
        return
    options = [o.strip() for o in fo.split(":")]
    invalid = [o for o in options if o not in _VALID_FO_CHARS]
    if invalid:
        result.checks.append(
            CheckResult(
                name="Forensic Options (fo=)",
                status=Status.ERROR,
                value=fo,
                details=[
                    f"fo= contains invalid option(s): {', '.join(invalid)}. "
                    "Valid values are 0, 1, d, s (colon-separated) (RFC 7489 §6.4)."
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(name="Forensic Options (fo=)", status=Status.INFO, value=fo)
        )


def _check_ri(tags: dict[str, str], result: DMARCResult) -> None:
    """Validate the ``ri=`` reporting interval tag (RFC 7489 §6.4).

    Must be a positive integer (seconds between aggregate reports).
    Default is 86400 (24 hours).

    :param tags: Parsed tag dictionary.
    :param result: Result object to append to.
    """
    ri = tags.get("ri", "")
    if not ri:
        return
    try:
        ri_int = int(ri)
        if ri_int <= 0:
            raise ValueError
    except ValueError:
        result.checks.append(
            CheckResult(
                name="Reporting Interval (ri=)",
                status=Status.ERROR,
                value=ri,
                details=[
                    "ri= must be a positive integer (seconds) (RFC 7489 §6.4). "
                    "Default is 86400 (24 hours)."
                ],
            )
        )
        return
    result.checks.append(
        CheckResult(
            name="Reporting Interval (ri=)",
            status=Status.INFO,
            value=f"{ri_int}s",
            details=[f"Aggregate reports requested every {ri_int} seconds."],
        )
    )


def _check_reporting_uris(
    tag: str,
    label: str,
    domain: str,
    tags: dict[str, str],
    result: DMARCResult,
) -> None:
    """Validate ``rua=`` or ``ruf=`` reporting URI tags (RFC 7489 §6.4, §7.1).

    For each URI in the comma-separated list:

    1. Scheme must be ``mailto:`` or ``https:`` (§6.4).
    2. For ``mailto:`` URIs, the address must be syntactically valid (§10.1.2).
    3. When the URI host differs from the assessed domain's organisational domain,
       the external destination verification DNS record must exist (§7.1):
       ``<assessed-domain>._report._dmarc.<report-host>`` must return a TXT
       record containing ``v=DMARC1``.

    :param tag: Tag name (``\"rua\"`` or ``\"ruf\"``).
    :type tag: str
    :param label: Human-readable check label.
    :type label: str
    :param domain: The assessed domain.
    :type domain: str
    :param tags: Parsed DMARC tag dictionary.
    :type tags: dict[str, str]
    :param result: Result object to append to.
    :type result: DMARCResult
    """
    raw = tags.get(tag, "")
    if not raw:
        if tag == "rua":
            result.checks.append(
                CheckResult(
                    name=label,
                    status=Status.WARNING,
                    details=[
                        "No rua= tag. "
                        "You will not receive aggregate DMARC reports (RFC 7489 §6.4)."
                    ],
                )
            )
        return

    uris = [u.strip() for u in raw.split(",") if u.strip()]
    uri_errors: list[str] = []
    uri_warnings: list[str] = []
    uri_infos: list[str] = []

    for uri in uris:
        parsed = urllib.parse.urlparse(uri)
        scheme = parsed.scheme.lower()

        # Scheme check (§6.4)
        if scheme not in _VALID_URI_SCHEMES:
            uri_errors.append(
                f"{uri!r}: unsupported scheme '{scheme}'. "
                "Only mailto: and https: are allowed (RFC 7489 §6.4)."
            )
            continue

        # mailto: address syntax (§10.1.2)
        if scheme == "mailto":
            address = parsed.path
            if not _MAILTO_RE.match(address):
                uri_errors.append(f"{uri!r}: '{address}' is not a valid email address.")
                continue
            report_host = address.split("@", 1)[1]
        else:
            report_host = parsed.hostname or ""

        # External destination verification (§7.1)
        # Only required when the report host's organisational domain differs
        # from the assessed domain.  We use a simple eSLD heuristic: the last
        # two labels of each domain.
        org_domain = _org_domain(domain)
        report_org = _org_domain(report_host)

        if report_org and report_org != org_domain:
            verification_name = f"{domain}._report._dmarc.{report_host}"
            txt_records = resolve(verification_name, "TXT") or []
            authorized = any("v=DMARC1" in r.strip('"') for r in txt_records)
            if authorized:
                uri_infos.append(
                    f"{uri!r}: external destination verified "
                    f"({verification_name} → v=DMARC1 found)."
                )
            else:
                uri_warnings.append(
                    f"{uri!r}: external destination NOT verified. "
                    f"No TXT record containing v=DMARC1 found at "
                    f"{verification_name!r} (RFC 7489 §7.1). "
                    "Mail receivers are required to ignore this URI."
                )
        else:
            uri_infos.append(
                f"{uri!r}: same organisational domain — no external verification needed."
            )

    if uri_errors:
        result.checks.append(
            CheckResult(
                name=label,
                status=Status.ERROR,
                value=raw,
                details=uri_errors + uri_warnings + uri_infos,
            )
        )
    elif uri_warnings:
        result.checks.append(
            CheckResult(
                name=label,
                status=Status.WARNING,
                value=raw,
                details=uri_warnings + uri_infos,
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name=label,
                status=Status.OK,
                value=raw,
                details=uri_infos,
            )
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _org_domain(domain: str) -> str:
    """Return a simple organisational domain approximation (last two labels).

    This is not a full Public Suffix List lookup but is sufficient for the
    common case where the report destination and the assessed domain share
    an eSLD.

    :param domain: A domain name string, e.g. ``\"mail.example.com\"``.
    :type domain: str
    :returns: The last two labels, e.g. ``\"example.com\"``, or the whole
        domain if it has fewer than two labels.
    :rtype: str
    """
    labels = domain.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain
