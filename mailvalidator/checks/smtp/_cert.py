"""Certificate parsing and validation checks."""

from __future__ import annotations

from datetime import datetime, timezone

from mailvalidator.models import CheckResult, Status, TLSDetails

from ._classify import _classify_ec_curve


def _cert_info(der: bytes) -> dict:
    """Parse a DER-encoded X.509 certificate and return a flat metadata dict.

    Requires the *cryptography* package (already a project dependency).

    :param der: DER-encoded certificate bytes.
    :type der: bytes
    :returns: Dict with keys ``subject``, ``issuer``, ``not_after``,
        ``sig_alg``, ``san``, ``pubkey_type``, ``pubkey_bits``,
        ``pubkey_curve``.  Returns ``{}`` if parsing fails so callers can
        use :meth:`dict.get` safely.
    :rtype: dict
    """
    try:
        import cryptography.hazmat.primitives.asymmetric.ec as _ec
        import cryptography.hazmat.primitives.asymmetric.rsa as _rsa
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        info: dict = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "sig_alg": (
                cert.signature_hash_algorithm.name
                if cert.signature_hash_algorithm
                else "unknown"
            ),
        }

        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            info["san"] = [n.value for n in san_ext.value]
        except x509.ExtensionNotFound:
            info["san"] = []

        pub = cert.public_key()
        if isinstance(pub, _rsa.RSAPublicKey):
            info.update(pubkey_type="RSA", pubkey_bits=pub.key_size, pubkey_curve="")
        elif isinstance(pub, _ec.EllipticCurvePublicKey):
            info.update(
                pubkey_type="EC", pubkey_bits=pub.key_size, pubkey_curve=pub.curve.name
            )
        else:
            info.update(pubkey_type=type(pub).__name__, pubkey_bits=0, pubkey_curve="")

        return info
    except Exception:
        return {}


def _check_certificate(
    details: TLSDetails,
    checks: list[CheckResult],
    host: str,
) -> None:
    """Report trust chain, public key, signature algorithm, domain match, and expiry.

    :param details: TLS details object containing parsed certificate metadata.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which :class:`~mailvalidator.models.CheckResult`
        items are appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    :param host: Hostname used in the SMTP connection; checked against the
        certificate SAN/CN.
    :type host: str
    """
    if not details.cert_subject:
        checks.append(
            CheckResult(
                name="Certificate",
                status=Status.INFO,
                details=["No certificate information available."],
            )
        )
        return

    # Trust chain
    if details.cert_trusted is True:
        trust_status, trust_value, trust_detail = Status.GOOD, "Trusted", []
    elif details.cert_trusted is False:
        trust_status = Status.WARNING
        trust_value = "Untrusted / self-signed"
        trust_detail = [
            "Certificate chain could not be verified against the system trust store. "
            "The certificate may be self-signed or issued by an unknown CA."
        ]
    else:
        trust_status = Status.INFO
        trust_value = "Unknown"
        trust_detail = [
            "Chain-of-trust could not be checked "
            "(bare IP address or connection failure during verification)."
        ]
    checks.append(
        CheckResult(
            name="Certificate Trust Chain",
            status=trust_status,
            value=trust_value,
            details=trust_detail,
        )
    )

    # Public key strength
    pk_type = details.cert_pubkey_type
    pk_bits = details.cert_pubkey_bits
    pk_curve = details.cert_pubkey_curve

    if pk_type == "RSA":
        if pk_bits >= 3072:
            pk_status, pk_note = Status.GOOD, ""
        elif pk_bits >= 2048:
            pk_status, pk_note = (
                Status.SUFFICIENT,
                "2048-bit RSA is acceptable but ≥3072 bit is recommended.",
            )
        else:
            pk_status, pk_note = (
                Status.INSUFFICIENT,
                f"{pk_bits}-bit RSA key is too short; reissue with ≥2048 bit.",
            )
        checks.append(
            CheckResult(
                name="Certificate Public Key",
                status=pk_status,
                value=f"RSA {pk_bits} bit",
                details=[pk_note] if pk_note else [],
            )
        )
    elif pk_type == "EC":
        curve_status = _classify_ec_curve(pk_curve)
        checks.append(
            CheckResult(
                name="Certificate Public Key",
                status=curve_status,
                value=f"EC {pk_curve} ({pk_bits} bit)",
                details=(
                    [f"Curve {pk_curve} is deprecated; reissue with P-256 or P-384."]
                    if curve_status == Status.PHASE_OUT
                    else [f"Curve {pk_curve} is not recommended."]
                    if curve_status == Status.INSUFFICIENT
                    else []
                ),
            )
        )
    else:
        checks.append(
            CheckResult(
                name="Certificate Public Key", status=Status.INFO, value=pk_type
            )
        )

    # Signature algorithm
    sig_alg = details.cert_sig_alg.lower()
    if any(h in sig_alg for h in ("sha256", "sha384", "sha512")):
        sig_status = Status.GOOD
    elif any(h in sig_alg for h in ("sha1", "md5")):
        sig_status = Status.INSUFFICIENT
    else:
        sig_status = Status.INFO
    checks.append(
        CheckResult(
            name="Certificate Signature",
            status=sig_status,
            value=details.cert_sig_alg,
            details=(
                [
                    "SHA-1/MD5 signatures are cryptographically broken; reissue the certificate with SHA-256+."
                ]
                if sig_status == Status.INSUFFICIENT
                else []
            ),
        )
    )

    # Domain match: SAN takes precedence over CN (RFC 6125)
    hostname = host.lower()
    san = details.cert_san
    if san:
        matched = any(
            hostname == n.lower()
            or (n.startswith("*.") and hostname.endswith(n[1:].lower()))
            for n in san
        )
    else:
        matched = f"cn={hostname}" in details.cert_subject.lower()

    checks.append(
        CheckResult(
            name="Certificate Domain Match",
            status=Status.OK if matched else Status.WARNING,
            value="Match" if matched else "Mismatch",
            details=[]
            if matched
            else [
                f"Hostname '{host}' not found in certificate SAN/CN. "
                "Note: SMTP senders typically ignore name mismatch unless DANE-TA is used."
            ],
        )
    )

    # Expiry
    if details.cert_not_after:
        try:
            expiry = datetime.fromisoformat(details.cert_not_after)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(tz=timezone.utc)).days
            if days_left < 0:
                exp_status, exp_detail = Status.ERROR, ["Certificate has EXPIRED."]
            elif days_left < 30:
                exp_status, exp_detail = (
                    Status.WARNING,
                    [f"Certificate expires in {days_left} day(s) – renew soon."],
                )
            else:
                exp_status, exp_detail = (
                    Status.OK,
                    [f"Valid for {days_left} more days (expires {expiry.date()})."],
                )
            checks.append(
                CheckResult(
                    name="Certificate Expiry",
                    status=exp_status,
                    value=str(expiry.date()),
                    details=exp_detail,
                )
            )
        except ValueError:
            checks.append(
                CheckResult(
                    name="Certificate Expiry",
                    status=Status.INFO,
                    value=details.cert_not_after,
                )
            )
