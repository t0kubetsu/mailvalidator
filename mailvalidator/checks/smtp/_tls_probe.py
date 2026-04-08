"""TLS probe and cipher enumeration infrastructure."""

from __future__ import annotations

import ssl
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed

from mailvalidator.models import TLSDetails

from ._cert import _cert_info
from ._connection import (
    _connect_plain,
    _is_ip,
    _no_verify_ctx,
    _set_sni,
    _starttls_and_get_cipher,
    _TIMEOUT,
)

# ---------------------------------------------------------------------------
# TLS version probing
# ---------------------------------------------------------------------------

_TLS_VERSION_PROBES: list[tuple[str, ssl.TLSVersion, ssl.TLSVersion]] = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
]
for _label, _attr in (("TLSv1.1", "TLSv1_1"), ("TLSv1", "TLSv1")):
    if hasattr(ssl.TLSVersion, _attr):
        _v = getattr(ssl.TLSVersion, _attr)
        _TLS_VERSION_PROBES.append((_label, _v, _v))

# Versions whose weak ciphers require SECLEVEL=0 to be accepted locally.
_LEGACY_TLS_VERSIONS: frozenset[ssl.TLSVersion] = frozenset(
    getattr(ssl.TLSVersion, attr)
    for attr in ("TLSv1", "TLSv1_1")
    if hasattr(ssl.TLSVersion, attr)
)


def _probe_single_tls_version(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
) -> bool:  # pragma: no cover
    """Return ``True`` if the server completes STARTTLS at exactly this TLS version.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param tls_min: Minimum TLS version (pinned equal to *tls_max*).
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version (pinned equal to *tls_min*).
    :type tls_max: ssl.TLSVersion
    :rtype: bool
    """
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException):
        return False
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return False

        ctx = _no_verify_ctx(tls_min, tls_max)
        if tls_min in _LEGACY_TLS_VERSIONS:
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass

        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        smtp.quit()
        return True
    except (smtplib.SMTPException, ssl.SSLError, OSError, ValueError):
        try:
            smtp.close()
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------
# Cipher enumeration
# ---------------------------------------------------------------------------

_TLS13_CIPHERSUITES: list[str] = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
]

_TLS12_AND_BELOW_CIPHERS: list[str] = [
    # Good – ECDHE-ECDSA + AEAD
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    # Good – ECDHE-RSA + AEAD
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256",
    # Sufficient – ECDHE + CBC
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA",
    # Sufficient – DHE-RSA
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES128-SHA",
    # Phase-out – RSA key exchange (no forward secrecy)
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES256-SHA",
    "AES128-SHA256",
    "AES128-SHA",
    # Phase-out – 3DES (Sweet32)
    "ECDHE-ECDSA-DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "DHE-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
]

_ALL_KNOWN_CIPHERS: list[str] = _TLS13_CIPHERSUITES + _TLS12_AND_BELOW_CIPHERS


def _make_cipher_probe_ctx(
    cipher: str,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
    seclevel0: bool = False,
) -> ssl.SSLContext:
    """Build a no-verify :class:`ssl.SSLContext` restricted to one cipher and version range.

    :param cipher: OpenSSL cipher name to restrict the context to.
    :type cipher: str
    :param tls_min: Minimum TLS version.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version.
    :type tls_max: ssl.TLSVersion
    :param seclevel0: When ``True``, append ``":@SECLEVEL=0"`` to the cipher string.
    :type seclevel0: bool
    :returns: Configured no-verify :class:`ssl.SSLContext`.
    :rtype: ssl.SSLContext
    :raises ssl.SSLError: If *cipher* is not recognised by OpenSSL.
    """
    ctx = _no_verify_ctx(tls_min, tls_max)

    if tls_min != ssl.TLSVersion.TLSv1_3:
        cipher_str = f"{cipher}:@SECLEVEL=0" if seclevel0 else cipher
        ctx.set_ciphers(cipher_str)
        try:
            ctx.set_ciphersuites("")  # type: ignore[attr-defined]
        except (ssl.SSLError, AttributeError):
            pass

    return ctx


def _try_cipher(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    cipher: str,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
    seclevel0: bool = False,
) -> bool:  # pragma: no cover
    """Return ``True`` if the server accepts *cipher* for the given TLS version.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param cipher: OpenSSL cipher name to probe.
    :type cipher: str
    :param tls_min: Minimum TLS version.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version.
    :type tls_max: ssl.TLSVersion
    :param seclevel0: Lower OpenSSL SECLEVEL to 0 for legacy cipher support.
    :type seclevel0: bool
    :rtype: bool
    """
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException):
        return False
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return False
        ctx = _make_cipher_probe_ctx(cipher, tls_min, tls_max, seclevel0=seclevel0)
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        smtp.quit()
        return True
    except (smtplib.SMTPException, ssl.SSLError, OSError, ValueError):
        try:
            smtp.close()
        except Exception:
            pass
        return False


def _enumerate_tls13_ciphers(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
) -> list[str]:  # pragma: no cover
    """Return the accepted TLS 1.3 ciphersuites in server-preference order.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :returns: Accepted TLS 1.3 suite names in server-preference order.
    :rtype: list[str]
    """
    has_set_ciphersuites = hasattr(
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), "set_ciphersuites"
    )
    accepted: set[str] = set()

    if has_set_ciphersuites:
        for suite in _TLS13_CIPHERSUITES:
            ctx = _no_verify_ctx(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
            ctx.set_ciphersuites(suite)  # type: ignore[attr-defined]
            negotiated = _starttls_and_get_cipher(
                host, port, helo_domain, sni_hostname, ctx
            )
            if negotiated == suite:
                accepted.add(suite)
    else:
        ctx = _no_verify_ctx(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
        negotiated = _starttls_and_get_cipher(
            host, port, helo_domain, sni_hostname, ctx
        )
        if negotiated in _TLS13_CIPHERSUITES:
            accepted.update(_TLS13_CIPHERSUITES)

    return [s for s in _TLS13_CIPHERSUITES if s in accepted]


def _enumerate_ciphers_for_version(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
    *,
    max_workers: int = 10,
) -> list[str]:  # pragma: no cover
    """Return accepted ciphers for one TLS version in server-preference order.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param tls_min: Minimum TLS version to pin the probe to.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version to pin the probe to.
    :type tls_max: ssl.TLSVersion
    :param max_workers: Maximum parallel threads for phase 1.  Defaults to ``10``.
    :type max_workers: int
    :returns: Accepted cipher names in server-preference order.
    :rtype: list[str]
    """
    if tls_min == ssl.TLSVersion.TLSv1_3:
        return _enumerate_tls13_ciphers(host, port, helo_domain, sni_hostname)

    is_legacy = tls_min in _LEGACY_TLS_VERSIONS

    # Phase 1: parallel acceptance probe
    accepted: set[str] = set()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _try_cipher,
                host,
                port,
                helo_domain,
                sni_hostname,
                c,
                tls_min,
                tls_max,
                is_legacy,
            ): c
            for c in _TLS12_AND_BELOW_CIPHERS
        }
        for fut in as_completed(futures):
            try:
                if fut.result():
                    accepted.add(futures[fut])
            except Exception:
                pass

    if not accepted:
        return []

    # Phase 2: reconstruct server-preference order
    remaining = list(accepted)
    ordered: list[str] = []

    while remaining:
        if len(remaining) == 1:
            ordered.append(remaining.pop())
            break

        cipher_list = ":".join(remaining)
        if is_legacy:
            cipher_list += ":@SECLEVEL=0"

        ctx = _no_verify_ctx(tls_min, tls_max)
        try:
            ctx.set_ciphers(cipher_list)
        except ssl.SSLError:
            ordered.extend(remaining)
            break

        chosen = _starttls_and_get_cipher(host, port, helo_domain, sni_hostname, ctx)
        if chosen and chosen in remaining:
            ordered.append(chosen)
            remaining.remove(chosen)
        else:
            ordered.extend(remaining)
            break

    return ordered


def _detect_server_cipher_order(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    accepted: list[str],
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
) -> bool | None:  # pragma: no cover
    """Return ``True`` if the server enforces its own cipher-preference order.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param accepted: Ordered list of accepted cipher names from the initial
        enumeration; at least two are required.
    :type accepted: list[str]
    :param tls_min: Minimum TLS version pin.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version pin.
    :type tls_max: ssl.TLSVersion
    :returns: ``True`` if server enforces order, ``False`` if it follows the
        client, ``None`` if the result could not be determined.
    :rtype: bool or None
    """
    if tls_min == ssl.TLSVersion.TLSv1_3:
        return True

    if len(accepted) < 2:
        return None

    a, b = accepted[0], accepted[1]
    is_legacy = tls_min in _LEGACY_TLS_VERSIONS

    def _pick(first: str, second: str) -> str | None:
        cipher_list = f"{first}:{second}"
        if is_legacy:
            cipher_list += ":@SECLEVEL=0"
        ctx = _no_verify_ctx(tls_min, tls_max)
        try:
            ctx.set_ciphers(cipher_list)
        except ssl.SSLError:
            return None
        return _starttls_and_get_cipher(host, port, helo_domain, sni_hostname, ctx)

    pick_ab = _pick(a, b)
    pick_ba = _pick(b, a)

    if pick_ab is None or pick_ba is None:
        return None
    return pick_ab == pick_ba


# ---------------------------------------------------------------------------
# Version map: label → (TLSVersion min, TLSVersion max)
# ---------------------------------------------------------------------------


def _build_version_map() -> dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]]:
    """Build the label-to-version-range map for all supported TLS versions.

    :returns: Mapping of TLS version label to ``(min, max)`` version tuple.
    :rtype: dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]]
    """
    m: dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]] = {
        "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    }
    for attr, label in (("TLSv1_1", "TLSv1.1"), ("TLSv1", "TLSv1")):
        if hasattr(ssl.TLSVersion, attr):
            v = getattr(ssl.TLSVersion, attr)
            m[label] = (v, v)
    return m


_VERSION_MAP: dict[str, tuple[ssl.TLSVersion, ssl.TLSVersion]] = _build_version_map()


# ---------------------------------------------------------------------------
# TLS probe – collects deep session metadata via STARTTLS
# ---------------------------------------------------------------------------


def _probe_tls(
    host: str,
    port: int,
    helo_domain: str,
) -> tuple[TLSDetails | None, str, str | None]:  # pragma: no cover
    """Connect via STARTTLS and populate a :class:`~mailvalidator.models.TLSDetails` object.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :returns: Tuple of ``(details, error_message, sni_hostname)``.
        On failure *details* is ``None`` and *error_message* is non-empty.
    :rtype: tuple[TLSDetails or None, str, str or None]
    """
    sni_hostname: str | None = None if _is_ip(host) else host
    details = TLSDetails()

    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException) as exc:
        return None, str(exc), None

    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return None, "STARTTLS not advertised", None

        ctx = _no_verify_ctx()
        if not sni_hostname:
            ctx.check_hostname = False
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        smtp.ehlo(helo_domain)
    except (smtplib.SMTPException, ValueError) as exc:
        return None, f"STARTTLS failed: {exc}", None

    raw = smtp.sock
    if not isinstance(raw, ssl.SSLSocket):
        smtp.quit()
        return None, "Socket is not an SSLSocket after STARTTLS", None

    details.tls_version = raw.version() or ""
    cipher_info = raw.cipher()
    if cipher_info:
        details.cipher_name = cipher_info[0]
        details.cipher_bits = cipher_info[2] or 0
    details.compression = raw.compression() or ""

    try:
        sslobj = getattr(raw, "_sslobj", None)
        group_fn = getattr(sslobj, "group", None) if sslobj else None
        if callable(group_fn):
            details.dh_group = group_fn() or ""
    except Exception:
        pass

    der = raw.getpeercert(binary_form=True)
    if der:
        details._cert_der = der  # type: ignore[attr-defined]
        info = _cert_info(der)
        details.cert_subject = info.get("subject", "")
        details.cert_issuer = info.get("issuer", "")
        details.cert_san = info.get("san", [])
        details.cert_not_after = info.get("not_after", "")
        details.cert_sig_alg = info.get("sig_alg", "")
        details.cert_pubkey_type = info.get("pubkey_type", "")
        details.cert_pubkey_bits = info.get("pubkey_bits", 0)
        details.cert_pubkey_curve = info.get("pubkey_curve", "")

        if sni_hostname:
            try:
                chain_ctx = ssl.create_default_context()
                chain_ctx.check_hostname = False
                chain_smtp = smtplib.SMTP(timeout=_TIMEOUT)
                chain_smtp.connect(host, port)
                chain_smtp.ehlo(helo_domain)
                chain_smtp._host = sni_hostname  # type: ignore[attr-defined]
                chain_smtp.starttls(context=chain_ctx)
                try:
                    chain_smtp.quit()
                except Exception:
                    pass
                details.cert_trusted = True
            except ssl.SSLCertVerificationError:
                details.cert_trusted = False
            except (OSError, smtplib.SMTPException):
                details.cert_trusted = None
        else:
            details.cert_trusted = None

    try:
        details.secure_renegotiation = raw.get_channel_binding("tls-unique") is not None
    except Exception:
        details.secure_renegotiation = None

    try:
        smtp.quit()
    except Exception:
        pass

    return details, "", sni_hostname
