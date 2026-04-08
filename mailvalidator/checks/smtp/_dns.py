"""CAA record and DANE/TLSA checks."""

from __future__ import annotations

import hashlib

from mailvalidator.models import CheckResult, Status

# NOTE: `resolve` is imported lazily inside _check_caa and _check_dane so that
# patch("mailvalidator.checks.smtp.resolve", …) intercepts the right binding
# in tests.

from ._connection import _connect_plain, _no_verify_ctx, _set_sni


def _parse_caa_record(record: str) -> tuple[int, str, str] | None:
    """Parse a single CAA record string into ``(flags, tag, value)``.

    CAA records have the format ``<flags> <tag> <value>`` where flags is an
    integer 0–255, tag is a lower-case ASCII string, and value is a quoted
    or unquoted string.

    :param record: Raw CAA record string from DNS (e.g. ``'0 issue "letsencrypt.org"'``).
    :type record: str
    :returns: ``(flags, tag, value)`` tuple, or ``None`` if the record is malformed.
    :rtype: tuple[int, str, str] or None
    """
    parts = record.split(None, 2)
    if len(parts) < 3:
        return None
    try:
        flags = int(parts[0])
    except ValueError:
        return None
    tag = parts[1].lower()
    value = parts[2].strip('"').strip()
    return flags, tag, value


def _check_caa(host: str, checks: list[CheckResult]) -> None:
    """Look up CAA records, walking up the DNS hierarchy from *host*.

    RFC 8659 requires at least one ``issue`` or ``issuewild`` tag to restrict
    which CAs may issue certificates for the domain.  Key checks:

    - **C1** ``issuewild`` is validated separately from ``issue``; a domain may
      restrict non-wildcard and wildcard issuance independently.
    - **C2** ``issue ";"`` (deny-all) is distinguished from a named CA and
      reported explicitly.
    - **C4** The flags byte is inspected; flag bit 0 (value 128, "issuer
      critical") is reported when present.
    - **C5** ``iodef`` URLs are validated for scheme; any non-HTTPS/non-mailto
      scheme is flagged.

    :param host: MX hostname to start the DNS hierarchy walk from.
    :type host: str
    :param checks: List to which a :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    from mailvalidator.checks.smtp import resolve  # noqa: PLC0415

    labels = host.rstrip(".").split(".")
    caa_records: list[str] = []
    found_at = ""

    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        records = resolve(candidate, "CAA")
        if records:
            caa_records = records
            found_at = candidate
            break

    if not caa_records:
        checks.append(
            CheckResult(
                name="CAA Records",
                status=Status.WARNING,
                details=[
                    f"No CAA records found for {host} or any parent domain. "
                    "Any CA can currently issue certificates for this domain."
                ],
            )
        )
        return

    # Parse all records into (flags, tag, value) triples.
    parsed: list[tuple[int, str, str]] = []
    malformed: list[str] = []
    for record in caa_records:
        parts = record.split(None, 2)
        if len(parts) < 3:
            malformed.append(record)
            continue
        try:
            flags = int(parts[0])
        except ValueError:
            malformed.append(record)
            continue
        parsed.append((flags, parts[1].lower(), parts[2].strip('"').strip()))

    # Collect by tag.
    issue_vals = [v for _, t, v in parsed if t == "issue"]
    issuewild_vals = [v for _, t, v in parsed if t == "issuewild"]
    iodef_vals = [v for _, t, v in parsed if t == "iodef"]

    # These produce WARNING status.
    hard_issues: list[str] = []
    # These are informational notes (shown in details, don't flip status to WARNING).
    info_notes: list[str] = []

    # C4: Critical flag (128) on an unrecognised tag.
    known_tags = {"issue", "issuewild", "iodef"}
    for flags, tag, _val in parsed:
        if (flags & 128) and tag not in known_tags:
            hard_issues.append(
                f"Unrecognised critical tag '{tag}' with flag 128 — "
                "CAs must refuse issuance if they do not understand this tag."
            )

    # C1 + C2: issue= and issuewild= checked separately.
    def _is_deny_all(v: str) -> bool:
        return v in (";", "")

    if not issue_vals and not issuewild_vals:
        hard_issues.append(
            "No 'issue' or 'issuewild' tag found; add at least one CAA 'issue' record."
        )
    else:
        # issue=
        if not issue_vals:
            hard_issues.append(
                "No 'issue' tag found. Without it, 'issuewild' does not restrict "
                "non-wildcard certificate issuance."
            )
        elif all(_is_deny_all(v) for v in issue_vals):
            # C2: deny-all is valid and strict; note it informatively.
            info_notes.append(
                "issue tag is set to ';' (deny-all): no CA is authorised to issue "
                "non-wildcard certificates for this domain."
            )

        # issuewild= — C1: report separately.
        if not issuewild_vals:
            # C3: absence is an info note, NOT a hard issue — don't change status.
            info_notes.append(
                "No 'issuewild' tag found. 'issue' tag(s) also govern wildcard "
                "certificate issuance per RFC 8659 §4.1."
            )
        else:
            if all(_is_deny_all(v) for v in issuewild_vals):
                info_notes.append(
                    "issuewild tag is set to ';' (deny-all): no CA is authorised to "
                    "issue wildcard certificates for this domain."
                )
            # Permissive wildcard alongside deny-all non-wildcard — notable asymmetry.
            if all(_is_deny_all(v) for v in issue_vals) and any(
                not _is_deny_all(v) for v in issuewild_vals
            ):
                hard_issues.append(
                    "WARNING: 'issuewild' permits a CA for wildcards while 'issue' "
                    "denies all non-wildcard issuance — verify this is intentional."
                )

    # C5: iodef scheme.
    for val in iodef_vals:
        if val.startswith("https://") or val.startswith("mailto:"):
            pass  # valid
        elif val.startswith("http://"):
            hard_issues.append(f"iodef URL uses plain HTTP ({val!r}); switch to HTTPS.")
        else:
            hard_issues.append(
                f"iodef URL has an unsupported scheme ({val!r}); use https:// or mailto:."
            )

    if malformed:
        hard_issues.append(
            "One or more CAA records appear malformed (expected: flags tag value)."
        )

    checks.append(
        CheckResult(
            name="CAA Records",
            status=Status.OK if not hard_issues else Status.WARNING,
            value=f"{len(caa_records)} record(s) at {found_at}",
            details=caa_records + hard_issues + info_notes,
        )
    )


def _tlsa_fingerprint(der: bytes, selector: int, matching: int) -> str | None:
    """Compute a TLSA record fingerprint from a DER-encoded certificate.

    :param der: DER-encoded certificate bytes.
    :type der: bytes
    :param selector: ``0`` = full certificate DER;
        ``1`` = SubjectPublicKeyInfo (SPKI) DER.
    :type selector: int
    :param matching: ``0`` = exact hex match; ``1`` = SHA-256; ``2`` = SHA-512.
    :type matching: int
    :returns: Lowercase hex fingerprint string, or ``None`` for unsupported
        selector/matching combinations or parse errors.
    :rtype: str or None
    """
    try:
        if selector == 0:
            data = der
        elif selector == 1:
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )

            cert = _x509.load_der_x509_certificate(der)
            data = cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        else:
            return None

        if matching == 0:
            return data.hex()
        elif matching == 1:
            return hashlib.sha256(data).hexdigest()
        elif matching == 2:
            return hashlib.sha512(data).hexdigest()
        return None
    except Exception:
        return None


def _verify_tlsa_record(record_str: str, cert_der: bytes) -> tuple[bool, str]:
    """Compare one TLSA record against the server certificate.

    :param record_str: Raw DNS TLSA value, e.g. ``"3 1 1 abcdef…"``.
    :type record_str: str
    :param cert_der: DER-encoded server certificate bytes.
    :type cert_der: bytes
    :returns: Tuple ``(matches, description)`` where *matches* is ``True``
        when the record fingerprint matches the certificate.
    :rtype: tuple[bool, str]
    """
    parts = record_str.split()
    if len(parts) < 4:
        return False, f"Malformed TLSA record: {record_str!r}"
    try:
        usage, selector, matching = int(parts[0]), int(parts[1]), int(parts[2])
        dns_hex = "".join(parts[3:]).lower()
    except ValueError:
        return False, f"Could not parse TLSA fields: {record_str!r}"

    usage_name = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}.get(
        usage, str(usage)
    )
    selector_name = {0: "Cert", 1: "SPKI"}.get(selector, str(selector))
    matching_name = {0: "Full", 1: "SHA-256", 2: "SHA-512"}.get(matching, str(matching))
    label = (
        f"{usage_name}({usage}) {selector_name}({selector}) {matching_name}({matching})"
    )

    computed = _tlsa_fingerprint(cert_der, selector, matching)
    if computed is None:
        return False, f"{label}: fingerprint type not supported"
    if computed == dns_hex:
        return True, f"{label}: fingerprint matches ✔"
    return False, (
        f"{label}: fingerprint MISMATCH – DNS: {dns_hex[:32]}… / cert: {computed[:32]}…"
    )


def _fetch_cert_der(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
) -> bytes | None:  # pragma: no cover
    """Open a fresh STARTTLS connection and return the raw DER certificate.

    Used as a fallback when :func:`_probe_tls` did not store the DER (e.g.
    STARTTLS was not advertised during the main probe).

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :returns: Raw DER bytes, or ``None`` on any failure.
    :rtype: bytes or None
    """
    import smtplib

    try:
        smtp, _, _ = _connect_plain(host, port)
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return None
        ctx = _no_verify_ctx()
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        der = smtp.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
        try:
            smtp.quit()
        except Exception:
            pass
        return der
    except Exception:
        return None


def _check_dane(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    cert_der: bytes | None,
    checks: list[CheckResult],
) -> None:
    """Look up TLSA records and verify them against the live server certificate.

    DANE usages for MX servers (RFC 7672):

    - Usage 2 (``DANE-TA``) – trust anchor; certificate must chain to this record.
    - Usage 3 (``DANE-EE``) – end entity; certificate must match this record exactly.

    Usages 0 (``PKIX-TA``) and 1 (``PKIX-EE``) are PKIX-constrained; they are
    flagged as warnings rather than errors.

    DANE allows multiple TLSA records so that the next certificate can be
    pre-published before the current one expires.  Non-matching records during
    a valid rollover are expected and noted as informational.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port (used to form the TLSA owner name ``_<port>._tcp.<host>``).
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param cert_der: DER-encoded certificate stashed by :func:`_probe_tls`,
        or ``None`` to trigger a fresh fetch.
    :type cert_der: bytes or None
    :param checks: List to which :class:`~mailvalidator.models.CheckResult`
        items are appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    from mailvalidator.checks.smtp import resolve  # noqa: PLC0415

    tlsa_name = f"_{port}._tcp.{host}"
    records = resolve(tlsa_name, "TLSA")

    if not records:
        checks.append(
            CheckResult(
                name="DANE – TLSA Existence",
                status=Status.INFO,
                details=[f"No TLSA record at {tlsa_name}. DANE is not configured."],
            )
        )
        return

    recommended = [r for r in records if r.startswith("2 ") or r.startswith("3 ")]
    pkix_only = [r for r in records if r.startswith("0 ") or r.startswith("1 ")]
    all_verifiable = recommended + pkix_only  # D2: verify PKIX records too

    checks.append(
        CheckResult(
            name="DANE – TLSA Existence",
            status=Status.OK if recommended else Status.WARNING,
            value=f"{len(records)} TLSA record(s), {len(recommended)} with recommended usage",
            details=(
                recommended + pkix_only
                if recommended
                else [
                    "Only PKIX-TA(0)/PKIX-EE(1) usages found; "
                    "DANE-TA(2) or DANE-EE(3) are required for MX servers (RFC 7672)."
                ]
            ),
        )
    )

    # D6: DNSSEC is a hard prerequisite for DANE security (RFC 6698 §1).
    # Without a valid DNSSEC chain the TLSA records cannot be trusted, so an
    # attacker could substitute them.  We always emit this as WARNING to
    # remind operators to check DNSSEC even when we cannot verify it here.
    checks.append(
        CheckResult(
            name="DANE – DNSSEC Prerequisite",
            status=Status.WARNING,
            details=[
                "DANE security requires a valid DNSSEC chain over the TLSA record "
                "(RFC 6698 §1). Without DNSSEC an attacker can substitute TLSA records, "
                "making DANE protection ineffective. Ensure DNSSEC is enabled and "
                "fully validated for this zone before relying on DANE."
            ],
        )
    )

    if not all_verifiable:
        return

    # Certificate fingerprint verification
    from mailvalidator.checks.smtp import _fetch_cert_der  # noqa: PLC0415
    der = cert_der or _fetch_cert_der(host, port, helo_domain, sni_hostname)

    if der is None:
        checks.append(
            CheckResult(
                name="DANE – Certificate Match",
                status=Status.WARNING,
                details=[
                    "Could not retrieve the server certificate; TLSA fingerprints unverified."
                ],
            )
        )
    else:
        results = []
        for r in all_verifiable:
            ok, desc = _verify_tlsa_record(r, der)
            # D1: DANE-TA records — add best-effort caveat.
            if r.startswith("2 "):
                desc += (
                    " [DANE-TA: verified against end-entity cert as best-effort; "
                    "full chain verification requires the complete cert chain]"
                )
            # D2: label PKIX records.
            if r.startswith("0 ") or r.startswith("1 "):
                desc += " [PKIX-constrained usage]"
            results.append((ok, desc, r))

        n_match = sum(ok for ok, _, _ in results)
        n_recommended_match = sum(
            ok for ok, _, r in results if r.startswith("2 ") or r.startswith("3 ")
        )
        detail_lines = [desc for _, desc, _ in results]

        if n_recommended_match > 0 or (not recommended and n_match > 0):
            non_matching = len(results) - n_match
            if non_matching > 0:
                detail_lines.append(
                    f"{non_matching} non-matching record(s) appear to be pre-published "
                    "for the next certificate (rollover) — this is expected and correct."
                )
            checks.append(
                CheckResult(
                    name="DANE – Certificate Match",
                    status=Status.OK,
                    value=f"{n_match}/{len(results)} record(s) match",
                    details=detail_lines,
                )
            )
        else:
            detail_lines.append(
                "No TLSA record matches the server certificate. "
                "DANE-aware senders will reject mail from this server."
            )
            checks.append(
                CheckResult(
                    name="DANE – Certificate Match",
                    status=Status.ERROR,
                    value=f"0/{len(results)} records match",
                    details=detail_lines,
                )
            )

    # D5: Matching type 0 (exact hex) is discouraged by RFC 7671 §5.1.
    type0_records = [
        r for r in all_verifiable if len(r.split()) >= 3 and r.split()[2] == "0"
    ]
    if type0_records:
        checks.append(
            CheckResult(
                name="DANE – Matching Type",
                status=Status.INFO,
                details=[
                    f"{len(type0_records)} record(s) use matching type 0 (exact hex). "
                    "RFC 7671 §5.1 discourages this in favour of SHA-256(1) or SHA-512(2) "
                    "because it makes key rotation harder."
                ],
            )
        )

    # Rollover scheme assessment (recommended records only).
    if not recommended:
        return

    n_ee = sum(1 for r in recommended if r.startswith("3 "))
    n_ta = sum(1 for r in recommended if r.startswith("2 "))

    if len(recommended) >= 2:
        if n_ee >= 1 and n_ta >= 1:
            note, status = (
                "DANE-EE + DANE-TA (current cert + issuer CA) – recommended rollover scheme.",
                Status.OK,
            )
        elif n_ee >= 2:
            note, status = (
                "DANE-EE + DANE-EE (current + next cert) – recommended rollover scheme.",
                Status.OK,
            )
        else:
            note, status = (
                "Non-standard type combination; verify your rollover plan.",
                Status.WARNING,
            )
    else:
        note, status = (
            "Only one TLSA record present. Add a second record (next cert or issuer CA) for a safe rollover.",
            Status.WARNING,
        )

    checks.append(
        CheckResult(name="DANE – Rollover Scheme", status=status, details=[note])
    )
