"""TLS version, cipher, key-exchange, compression, and renegotiation checks."""

from __future__ import annotations

import ssl

from mailvalidator.models import CheckResult, Status, TLSDetails

from ._classify import (
    _CIPHER_ICON,
    _SHA_GOOD,
    _SHA_PHASE_OUT,
    _STATUS_RANK,
    _classify_cipher,
    _classify_ec_curve,
)

# NOTE: _tls_version_status is imported lazily inside its callers so that
# patch("mailvalidator.checks.smtp._tls_version_status", …) works in tests.
from ._tls_probe import _TLS_VERSION_PROBES, _VERSION_MAP

# NOTE: _probe_single_tls_version, _enumerate_ciphers_for_version, and
# _detect_server_cipher_order are imported lazily inside their callers so that
# patch("mailvalidator.checks.smtp._probe_single_tls_version", …) and friends
# intercept the right binding during tests.


def _check_tls_version(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    details: TLSDetails,
    checks: list[CheckResult],
) -> None:
    """Probe each TLS version individually and append a graded summary result.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param details: TLS details object; ``tls_version`` is used in the
        result value field.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which the new
        :class:`~mailvalidator.models.CheckResult` is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    from mailvalidator.checks.smtp import (  # noqa: PLC0415
        _probe_single_tls_version,
        _tls_version_status,
    )

    accepted: list[str] = []
    rejected: list[str] = []

    for label, tls_min, tls_max in _TLS_VERSION_PROBES:
        if _probe_single_tls_version(
            host, port, helo_domain, sni_hostname, tls_min, tls_max
        ):
            accepted.append(label)
        else:
            rejected.append(label)

    phase_out_accepted = [
        v for v in accepted if _tls_version_status(v) == Status.PHASE_OUT
    ]
    insufficient_accepted = [
        v for v in accepted if _tls_version_status(v) == Status.INSUFFICIENT
    ]

    if insufficient_accepted:
        overall = Status.INSUFFICIENT
    elif phase_out_accepted:
        overall = Status.PHASE_OUT
    elif any(_tls_version_status(v) == Status.OK for v in accepted):
        overall = Status.GOOD
    elif any(_tls_version_status(v) == Status.SUFFICIENT for v in accepted):
        overall = Status.SUFFICIENT
    else:
        overall = Status.INFO  # all probes failed or were blocked

    _MARKER = {
        "OK": "✔",
        "SUFFICIENT": "✔",
        "PHASE_OUT": "↓ phase-out",
        "INSUFFICIENT": "✘ insecure",
    }
    detail_lines = [
        f"  {_MARKER.get(_tls_version_status(v).value, '✔')}  {v} – accepted"
        for v in accepted
    ] + [f"  –  {v} – not accepted" for v in rejected]
    if phase_out_accepted:
        detail_lines.append(
            f"Disable: {', '.join(phase_out_accepted)} – deprecated protocol(s) still accepted."
        )
    if insufficient_accepted:
        detail_lines.append(
            f"CRITICAL – disable immediately: {', '.join(insufficient_accepted)} – insecure protocol(s) accepted."
        )

    checks.append(
        CheckResult(
            name="TLS Versions",
            status=overall,
            value=f"Best: {details.tls_version}"
            if details.tls_version
            else "negotiated version unknown",
            details=detail_lines,
        )
    )


def _check_cipher(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    details: TLSDetails,
    checks: list[CheckResult],
) -> None:
    """Enumerate accepted ciphers per TLS version and emit a graded result for each.

    Per-version ordered lists are stored on the dynamic attribute
    ``details.offered_ciphers_by_version`` so that :func:`_check_cipher_order`
    can reuse them without making a second round of network probes.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param details: TLS details object; ``offered_ciphers_by_version`` and
        ``offered_ciphers`` are populated as a side-effect.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which per-version
        :class:`~mailvalidator.models.CheckResult` items are appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    from mailvalidator.checks.smtp import _enumerate_ciphers_for_version  # noqa: PLC0415

    details.offered_ciphers_by_version: dict[str, list[str]] = {}  # type: ignore[attr-defined]

    for ver_label, (tls_min, tls_max) in _VERSION_MAP.items():
        ciphers = _enumerate_ciphers_for_version(
            host, port, helo_domain, sni_hostname, tls_min, tls_max
        )
        if not ciphers:
            continue

        details.offered_ciphers_by_version[ver_label] = ciphers  # type: ignore[attr-defined]

        ver_worst = Status.GOOD
        detail_lines: list[str] = []
        for c in ciphers:
            st = _classify_cipher(c)
            icon = _CIPHER_ICON.get(st.value, "?")
            detail_lines.append(f"  {icon} [{st.value}] {c}")
            if _STATUS_RANK.get(st, 0) > _STATUS_RANK.get(ver_worst, 0):
                ver_worst = st

        checks.append(
            CheckResult(
                name=f"Cipher Suites ({ver_label})",
                status=ver_worst,
                value=f"{len(ciphers)} cipher(s)",
                details=detail_lines,
            )
        )

    # Flat deduped list for backward compatibility with other checks
    seen: set[str] = set()
    flat: list[str] = []
    for lst in details.offered_ciphers_by_version.values():  # type: ignore[attr-defined]
        for c in lst:
            if c not in seen:
                seen.add(c)
                flat.append(c)
    details.offered_ciphers = flat


def _check_cipher_order(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    details: TLSDetails,
    checks: list[CheckResult],
) -> None:
    """Check server cipher-preference enforcement and prescribed ordering per version.

    Must be called after :func:`_check_cipher` so that
    ``details.offered_ciphers_by_version`` is populated.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param details: TLS details object; reads ``offered_ciphers_by_version``.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which per-version
        :class:`~mailvalidator.models.CheckResult` items are appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    by_version: dict[str, list[str]] = getattr(
        details, "offered_ciphers_by_version", {}
    )

    if not by_version:
        checks.append(
            CheckResult(
                name="Cipher Order",
                status=Status.INFO,
                details=["No cipher enumeration data available."],
            )
        )
        return

    order_rank = {
        Status.GOOD: 0,
        Status.SUFFICIENT: 1,
        Status.PHASE_OUT: 2,
        Status.INSUFFICIENT: 3,
    }

    for ver_label, ciphers in by_version.items():
        tls_min, tls_max = _VERSION_MAP.get(
            ver_label, (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        )

        # Server-preference enforcement
        from mailvalidator.checks.smtp import _detect_server_cipher_order  # noqa: PLC0415
        enforced = _detect_server_cipher_order(
            host, port, helo_domain, sni_hostname, ciphers, tls_min, tls_max
        )
        if enforced is True:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Server Preference ({ver_label})",
                    status=Status.OK,
                    value="Enforced",
                )
            )
        elif enforced is False:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Server Preference ({ver_label})",
                    status=Status.WARNING,
                    value="Not enforced",
                    details=[
                        "Server follows the client's cipher preference rather than its own."
                    ],
                )
            )
        else:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Server Preference ({ver_label})",
                    status=Status.INFO,
                    details=["Could not determine (need ≥2 accepted ciphers)."],
                )
            )

        # Prescribed ordering: Good → Sufficient → Phase-out
        categories = [_classify_cipher(c) for c in ciphers]
        ranks = [order_rank.get(s, 3) for s in categories]

        if set(categories) <= {Status.GOOD}:
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Prescribed Ordering ({ver_label})",
                    status=Status.NA,
                    value="N/A (all ciphers are Good)",
                )
            )
        elif ranks == sorted(ranks):
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Prescribed Ordering ({ver_label})",
                    status=Status.OK,
                    value="Correct",
                )
            )
        else:
            correct = sorted(
                ciphers, key=lambda c: order_rank.get(_classify_cipher(c), 3)
            )
            checks.append(
                CheckResult(
                    name=f"Cipher Order – Prescribed Ordering ({ver_label})",
                    status=Status.WARNING,
                    value="Incorrect",
                    details=[
                        "Ciphers should be ordered: Good → Sufficient → Phase-out.",
                        "Actual order:  " + ", ".join(ciphers),
                        "Recommended:   " + ", ".join(correct),
                    ],
                )
            )


def _check_key_exchange(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Assess the key exchange mechanism used in the negotiated TLS session.

    **TLS 1.3**: ephemeral ECDHE is mandatory (RFC 8446 §4.2.7).  Python ssl
    does not expose the negotiated ``NamedGroup`` on most builds; when the
    group name is unavailable the check reports ``GOOD`` with an informational
    note.

    **TLS ≤1.2**: the mechanism is inferred from the cipher name prefix:

    - ``ECDHE-*`` → EC Diffie-Hellman; the named curve is classified.
    - ``DHE-*``   → finite-field DH; assessed by key size in bits.
    - other        → static RSA key exchange (no forward secrecy; phase-out).

    :param details: TLS details object containing session metadata.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which :class:`~mailvalidator.models.CheckResult`
        items are appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    tls_ver = details.tls_version
    cipher = details.cipher_name

    # TLS 1.3 – always ephemeral ECDHE per RFC 8446
    if tls_ver == "TLSv1.3" and cipher.startswith("TLS_"):
        group = details.dh_group or ""
        if group:
            st = _classify_ec_curve(group)
            msg = (
                [f"Curve {group} is deprecated; prefer x25519 or secp256r1."]
                if st == Status.PHASE_OUT
                else [f"Curve {group} is not recommended for key exchange."]
                if st == Status.INSUFFICIENT
                else []
            )
            checks.append(
                CheckResult(
                    name="Key Exchange – EC Curve",
                    status=st,
                    value=f"ECDHE ({group})",
                    details=msg,
                )
            )
        else:
            checks.append(
                CheckResult(
                    name="Key Exchange – EC Curve",
                    status=Status.GOOD,
                    value="ECDHE (TLS 1.3 – group not exposed by this Python/OpenSSL build)",
                    details=[
                        "TLS 1.3 mandates ephemeral ECDHE (RFC 8446 §4.2.7). "
                        "Use testssl.sh to confirm the exact group."
                    ],
                )
            )
        return

    # TLS ≤1.2 – derive mechanism from cipher name prefix
    if "ECDHE" in cipher:
        curve = details.dh_group or ""  # NOTE: cert pubkey curve ≠ kex curve
        st = _classify_ec_curve(curve)
        msg = (
            [f"Curve {curve} is deprecated; migrate to secp256r1 or secp384r1."]
            if st == Status.PHASE_OUT
            else [f"Curve {curve} is not considered secure for key exchange."]
            if st == Status.INSUFFICIENT
            else [
                "EC curve not exposed by this Python/OpenSSL build; verify with testssl.sh."
            ]
            if st == Status.INFO
            else []
        )
        checks.append(
            CheckResult(
                name="Key Exchange – EC Curve",
                status=st,
                value=f"ECDHE ({curve})" if curve else "ECDHE (curve unknown)",
                details=msg,
            )
        )

    elif "DHE" in cipher:
        bits = details.dh_bits or 0
        if bits >= 3072:
            st2, note = Status.SUFFICIENT, ""
        elif bits >= 2048:
            st2, note = (
                Status.PHASE_OUT,
                "ffdhe2048 – phase-out; upgrade to ≥3072-bit group.",
            )
        elif bits > 0:
            st2, note = Status.INSUFFICIENT, f"{bits}-bit DH group is insecure."
        else:
            st2, note = (
                Status.INFO,
                "DH group size not exposed by this Python/OpenSSL build.",
            )
        checks.append(
            CheckResult(
                name="Key Exchange – DH Group",
                status=st2,
                value=f"{bits} bit" if bits else "unknown",
                details=[note] if note else [],
            )
        )

    else:
        # RSA key exchange: no forward secrecy
        checks.append(
            CheckResult(
                name="Key Exchange",
                status=Status.PHASE_OUT,
                value=f"RSA ({cipher})",
                details=[
                    "RSA key exchange provides no forward secrecy. Migrate to ECDHE or DHE ciphers."
                ],
            )
        )


def _check_hash_function(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Report the hash algorithm used to sign the key-exchange parameters.

    TLS 1.3 always uses HKDF with SHA-256 or SHA-384; no per-cipher
    inspection is needed.  For TLS ≤1.2 the hash is the last hyphen-delimited
    token of the cipher name (e.g. ``ECDHE-RSA-AES256-GCM-SHA384``).

    :param details: TLS details object; reads ``tls_version`` and
        ``cipher_name``.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which a :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    if details.tls_version == "TLSv1.3":
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)",
                status=Status.GOOD,
                value="SHA-256/384 (TLS 1.3 HKDF)",
            )
        )
        return

    found: str | None = None
    for part in details.cipher_name.lower().split("-"):
        if part in _SHA_GOOD or part in _SHA_PHASE_OUT:
            found = part.upper()
            break

    if found and found.lower() in _SHA_GOOD:
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)", status=Status.GOOD, value=found
            )
        )
    elif found:
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)",
                status=Status.PHASE_OUT,
                value=found,
                details=[
                    f"{found} is weak for key-exchange signatures; upgrade to SHA-256 or better."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Hash Function (Key Exchange)",
                status=Status.INFO,
                value="(unable to determine)",
            )
        )


def _check_compression(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Flag TLS-layer compression, which enables the CRIME attack (CVE-2012-4929).

    :param details: TLS details object; reads ``compression``.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which a :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    comp = details.compression
    if not comp:
        checks.append(
            CheckResult(
                name="TLS Compression",
                status=Status.GOOD,
                value="None",
                details=["No TLS-level compression (CRIME-safe)."],
            )
        )
    elif comp.lower() in ("deflate", "zlib"):
        checks.append(
            CheckResult(
                name="TLS Compression",
                status=Status.INSUFFICIENT,
                value=comp,
                details=[
                    "TLS-layer compression is enabled. Disable immediately to prevent CRIME attacks."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="TLS Compression",
                status=Status.SUFFICIENT,
                value=comp,
                details=[
                    "Application-level compression detected (not CRIME-vulnerable by itself)."
                ],
            )
        )


def _check_renegotiation(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Check for RFC 5746 secure renegotiation support.

    TLS 1.3 eliminates renegotiation entirely (replaced by Key Update); both
    sub-checks are reported as N/A.

    For TLS ≤1.2, secure-renegotiation support is inferred from the
    ``tls-unique`` channel binding: a non-null value implies the
    Renegotiation Info extension (RI) was exchanged, satisfying RFC 5746.

    Client-initiated renegotiation cannot be actively probed in pure Python
    (it would require sending a ``ClientHello`` mid-session); it is flagged
    for manual verification instead.

    :param details: TLS details object; reads ``tls_version`` and
        ``secure_renegotiation``.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which :class:`~mailvalidator.models.CheckResult`
        items are appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    if details.tls_version == "TLSv1.3":
        checks.append(
            CheckResult(
                name="Secure Renegotiation", status=Status.GOOD, value="N/A (TLS 1.3)"
            )
        )
        checks.append(
            CheckResult(
                name="Client-Initiated Renegotiation",
                status=Status.GOOD,
                value="N/A (TLS 1.3)",
            )
        )
        return

    sr = details.secure_renegotiation
    if sr is True:
        checks.append(
            CheckResult(
                name="Secure Renegotiation", status=Status.GOOD, value="Supported"
            )
        )
    elif sr is False:
        checks.append(
            CheckResult(
                name="Secure Renegotiation",
                status=Status.INSUFFICIENT,
                value="Not supported",
                details=[
                    "RFC 5746 Renegotiation Info extension absent; server may be vulnerable to renegotiation attacks."
                ],
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Secure Renegotiation",
                status=Status.INFO,
                value="(unable to determine)",
            )
        )

    checks.append(
        CheckResult(
            name="Client-Initiated Renegotiation",
            status=Status.INFO,
            details=[
                "Active probe not performed. Verify server-side configuration manually."
            ],
        )
    )
