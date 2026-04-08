"""SMTP protocol-level checks: banner FQDN, EHLO domain, ESMTP extensions,
VRFY command behaviour, and open relay test.
"""

from __future__ import annotations

import ipaddress
import re
import smtplib

from mailvalidator.models import CheckResult, Status

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimal FQDN pattern: at least two dot-separated labels, each 1–63 chars.
# Used to validate the domain token in 220 banners and EHLO 250 responses
# (RFC 5321 §4.1.3, §4.1.1.1).
_FQDN_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)"
    r"+[A-Za-z]{2,63}\.?$"
)


# ---------------------------------------------------------------------------
# Check: 220 banner FQDN (RFC 5321 §4.1.3)
# ---------------------------------------------------------------------------


def _check_banner_fqdn(banner: str, checks: list[CheckResult]) -> None:
    """Validate that the 220 greeting contains a valid FQDN (RFC 5321 §4.1.3).

    The greeting line MUST be of the form::

        220 <domain> Service ready

    where ``<domain>`` is the fully-qualified domain name of the server.
    A bare IP address is permitted only when the server has no domain name
    (RFC 5321 §4.1.3), but is flagged as a warning because public MX servers
    should have a hostname.

    :param banner: Raw 220 greeting string returned by the server (with or
        without the leading ``220`` code — smtplib strips the code prefix).
    :type banner: str
    :param checks: List to which a :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    # Strip a leading "220" or "220-" prefix that smtplib sometimes includes
    text = re.sub(r"^220[-\s]+", "", banner.strip(), flags=re.IGNORECASE)
    tokens = text.split()
    domain_token = tokens[0] if tokens else ""

    if not domain_token:
        checks.append(
            CheckResult(
                name="Banner FQDN (RFC 5321 §4.1.3)",
                status=Status.ERROR,
                details=["220 greeting is empty or missing the server domain name."],
            )
        )
        return

    # Bare IP is allowed but unusual for a public MX
    try:
        ipaddress.ip_address(domain_token.strip("[]"))
        checks.append(
            CheckResult(
                name="Banner FQDN (RFC 5321 §4.1.3)",
                status=Status.WARNING,
                value=domain_token,
                details=[
                    f"220 greeting identifies the server by IP address ({domain_token}) "
                    "rather than a hostname. Public MX servers should use a fully-qualified "
                    "domain name (RFC 5321 §4.1.3)."
                ],
            )
        )
        return
    except ValueError:
        pass  # not an IP — proceed to FQDN check

    if _FQDN_RE.match(domain_token):
        checks.append(
            CheckResult(
                name="Banner FQDN (RFC 5321 §4.1.3)",
                status=Status.OK,
                value=domain_token,
                details=[
                    f"220 greeting correctly identifies the server as {domain_token!r}."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Banner FQDN (RFC 5321 §4.1.3)",
                status=Status.ERROR,
                value=domain_token,
                details=[
                    f"{domain_token!r} does not look like a valid FQDN. "
                    "The 220 greeting MUST contain the server's fully-qualified domain name "
                    "(RFC 5321 §4.1.3)."
                ],
            )
        )


# ---------------------------------------------------------------------------
# Check: EHLO domain (RFC 5321 §4.1.1.1)
# ---------------------------------------------------------------------------


def _check_ehlo_domain(smtp: smtplib.SMTP, checks: list[CheckResult]) -> None:
    """Verify that the EHLO 250 response names a valid FQDN (RFC 5321 §4.1.1.1).

    The first line of the EHLO response MUST be of the form::

        250-<domain>   (more extensions follow)
        250 <domain>   (sole response line)

    where ``<domain>`` is the server's FQDN.  A bare IP in a domain literal
    (``[x.x.x.x]``) is RFC-conformant but unusual for a public MX.

    :param smtp: :class:`smtplib.SMTP` instance on which ``ehlo()`` has
        already been called; reads ``smtp.ehlo_resp``.
    :type smtp: smtplib.SMTP
    :param checks: List to which a :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    raw: bytes | None = getattr(smtp, "ehlo_resp", None)
    if not raw:
        checks.append(
            CheckResult(
                name="EHLO Domain (RFC 5321 §4.1.1.1)",
                status=Status.WARNING,
                details=["No EHLO response available to inspect."],
            )
        )
        return

    first_line = raw.decode(errors="replace").splitlines()[0] if raw else ""
    # Strip "250-" or "250 " prefix
    stripped = re.sub(r"^250[-\s]+", "", first_line.strip(), flags=re.IGNORECASE)
    tokens = stripped.split()
    domain_token = tokens[0] if tokens else ""

    if not domain_token:
        checks.append(
            CheckResult(
                name="EHLO Domain (RFC 5321 §4.1.1.1)",
                status=Status.ERROR,
                details=["EHLO 250 response does not include a domain name."],
            )
        )
        return

    # Domain literal [x.x.x.x] is RFC-conformant (RFC 5321 §2.3.5)
    if domain_token.startswith("[") and domain_token.endswith("]"):
        checks.append(
            CheckResult(
                name="EHLO Domain (RFC 5321 §4.1.1.1)",
                status=Status.WARNING,
                value=domain_token,
                details=[
                    f"EHLO response uses an IP domain literal {domain_token}. "
                    "Public MX servers should identify themselves with a FQDN (RFC 5321 §2.3.5)."
                ],
            )
        )
        return

    if _FQDN_RE.match(domain_token):
        checks.append(
            CheckResult(
                name="EHLO Domain (RFC 5321 §4.1.1.1)",
                status=Status.OK,
                value=domain_token,
                details=[
                    f"EHLO response correctly identifies server as {domain_token!r}."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="EHLO Domain (RFC 5321 §4.1.1.1)",
                status=Status.ERROR,
                value=domain_token,
                details=[
                    f"{domain_token!r} is not a valid FQDN. "
                    "The EHLO 250 response MUST include the server's domain name "
                    "(RFC 5321 §4.1.1.1)."
                ],
            )
        )


# ---------------------------------------------------------------------------
# Check: ESMTP extension advertisement (RFC 1870, RFC 2920, RFC 6152, RFC 6531)
# ---------------------------------------------------------------------------


def _check_extensions(smtp: smtplib.SMTP, checks: list[CheckResult]) -> None:
    """Report which ESMTP extensions the server advertises.

    Checks for extensions that well-configured MX servers are expected to
    support:

    * **STARTTLS** (RFC 3207) — encrypted transport; checked separately
    * **SIZE** (RFC 1870) — maximum message size declaration
    * **PIPELINING** (RFC 2920) — command batching for throughput
    * **8BITMIME** (RFC 6152) — 8-bit clean transport
    * **SMTPUTF8** (RFC 6531) — internationalised email addresses

    Absence of SIZE or PIPELINING is not an error but is worth noting.

    :param smtp: :class:`smtplib.SMTP` instance on which ``ehlo()`` has
        already been called.
    :type smtp: smtplib.SMTP
    :param checks: List to which a :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    advertised: list[str] = []
    missing: list[str] = []

    for ext, rfc_note in (
        ("SIZE", "RFC 1870"),
        ("PIPELINING", "RFC 2920"),
        ("8BITMIME", "RFC 6152"),
        ("SMTPUTF8", "RFC 6531"),
    ):
        if smtp.has_extn(ext):
            value = smtp.esmtp_features.get(ext.lower(), "")  # type: ignore[attr-defined]
            token = f"{ext}={value}" if value else ext
            advertised.append(f"{token} ({rfc_note})")
        else:
            missing.append(f"{ext} ({rfc_note})")

    details = []
    if advertised:
        details.append("Advertised: " + ", ".join(advertised))
    if missing:
        details.append("Not advertised: " + ", ".join(missing))

    checks.append(
        CheckResult(
            name="ESMTP Extensions",
            status=Status.OK if not missing else Status.INFO,
            value=f"{len(advertised)} of {len(advertised) + len(missing)} checked",
            details=details,
        )
    )


# ---------------------------------------------------------------------------
# Check: VRFY command (RFC 5321 §3.5.3)
# ---------------------------------------------------------------------------


def _check_vrfy(
    smtp: smtplib.SMTP, helo_domain: str, checks: list[CheckResult]
) -> None:  # pragma: no cover
    """Issue a VRFY probe and report the server's response (RFC 5321 §3.5.3).

    RFC 5321 §3.5.3 states that VRFY SHOULD be supported but that servers
    MAY return code 252 ("Cannot VRFY user, but will accept message and
    attempt delivery") as a privacy measure.  Code 502 ("Command not
    implemented") is common on anti-spam configurations.

    Result interpretation:

    * ``252`` — privacy-preserving: accepted but unverifiable (recommended)
    * other ``2xx`` — VRFY supported
    * ``502`` — command disabled (common, acceptable)
    * ``550``/``551`` — user unknown or forwarded (server responded)
    * Anything else — unexpected; noted as INFO

    :param smtp: :class:`smtplib.SMTP` instance on which ``ehlo()`` has
        already been called.
    :type smtp: smtplib.SMTP
    :param helo_domain: Domain used in the EHLO command (unused here but kept
        for API symmetry with other check functions).
    :type helo_domain: str
    :param checks: List to which a :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    try:
        code, msg = smtp.verify("postmaster")
    except smtplib.SMTPException as exc:
        code_str = str(exc)[:3]
        try:
            code = int(code_str)
        except ValueError:
            checks.append(
                CheckResult(
                    name="VRFY Command (RFC 5321 §3.5.3)",
                    status=Status.INFO,
                    details=[f"VRFY probe raised an exception: {exc}"],
                )
            )
            return
        msg = b""

    msg_str = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)

    if code == 252:
        checks.append(
            CheckResult(
                name="VRFY Command (RFC 5321 §3.5.3)",
                status=Status.OK,
                value="252",
                details=[
                    f"252 – server cannot verify but will attempt delivery ({msg_str.strip()}). "
                    "This is the recommended privacy-preserving response (RFC 5321 §3.5.3)."
                ],
            )
        )
    elif 200 <= code < 300:
        checks.append(
            CheckResult(
                name="VRFY Command (RFC 5321 §3.5.3)",
                status=Status.OK,
                value=str(code),
                details=[f"VRFY supported — {code} {msg_str.strip()}."],
            )
        )
    elif code == 502:
        checks.append(
            CheckResult(
                name="VRFY Command (RFC 5321 §3.5.3)",
                status=Status.INFO,
                value="502",
                details=[
                    "502 – VRFY command disabled. This is common on anti-spam configurations "
                    "and is acceptable (RFC 5321 §3.5.3 allows disabling VRFY)."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="VRFY Command (RFC 5321 §3.5.3)",
                status=Status.INFO,
                value=str(code),
                details=[f"VRFY returned {code}: {msg_str.strip()}."],
            )
        )


# ---------------------------------------------------------------------------
# Open relay test (RFC 5321 §3.9)
# ---------------------------------------------------------------------------


def _test_open_relay(smtp: smtplib.SMTP, helo_domain: str) -> bool:  # pragma: no cover
    """Return ``True`` if the server relays mail for two unrelated external addresses.

    Issues ``MAIL FROM`` and ``RCPT TO`` for addresses at distinct
    ``*.example`` domains.  If both return SMTP 250 the server is an open
    relay.  ``RSET`` is always sent to avoid leaving a partial transaction
    queued on the server.

    :param smtp: Active :class:`smtplib.SMTP` connection.
    :type smtp: smtplib.SMTP
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :rtype: bool
    """
    try:
        smtp.ehlo(helo_domain)
        code, _ = smtp.mail("relay-test@external-domain-test.example")
        if code != 250:
            return False
        code, _ = smtp.rcpt("relay-test@another-external-domain.example")
        try:
            smtp.rset()
        except smtplib.SMTPException:
            pass
        return code == 250
    except smtplib.SMTPException:
        return False
