"""Low-level SMTP / TLS connection primitives."""

from __future__ import annotations

import ipaddress
import smtplib
import ssl
import time

_TIMEOUT = 10  # seconds per blocking network call


def _is_ip(host: str) -> bool:
    """Return ``True`` if *host* is a bare IPv4 or IPv6 address (not a hostname).

    :param host: String to test.
    :type host: str
    :rtype: bool
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _connect_plain(
    host: str, port: int
) -> tuple[smtplib.SMTP, float, str]:  # pragma: no cover
    """Open a plain TCP connection to an SMTP server.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: TCP port to connect to.
    :type port: int
    :returns: Tuple of ``(smtp_client, connect_time_ms, banner_string)``.
    :rtype: tuple[smtplib.SMTP, float, str]
    :raises OSError: On TCP connection failure.
    :raises smtplib.SMTPException: On SMTP-level failure.
    """
    t0 = time.monotonic()
    smtp = smtplib.SMTP(timeout=_TIMEOUT)
    _code, msg = smtp.connect(host, port)
    elapsed_ms = (time.monotonic() - t0) * 1000
    banner = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
    return smtp, elapsed_ms, banner


def _no_verify_ctx(
    tls_min: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    tls_max: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
) -> ssl.SSLContext:
    """Return a ``TLS_CLIENT`` :class:`ssl.SSLContext` that accepts any certificate.

    Used for diagnostic probes where certificates are inspected manually
    rather than relying on the system trust store.

    :param tls_min: Minimum TLS version to negotiate.
    :type tls_min: ssl.TLSVersion
    :param tls_max: Maximum TLS version to negotiate.
    :type tls_max: ssl.TLSVersion
    :returns: A no-verify :class:`ssl.SSLContext`.
    :rtype: ssl.SSLContext
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = tls_min
    ctx.maximum_version = tls_max
    return ctx


def _set_sni(smtp: smtplib.SMTP, sni_hostname: str | None, fallback: str) -> None:
    """Set ``smtp._host`` so that smtplib passes the correct SNI ``server_hostname``.

    ``smtplib`` reads ``smtp._host`` when calling ``ssl.wrap_socket()``.
    When ``SMTP()`` is constructed without a host argument (our pattern:
    ``SMTP()`` then ``.connect()``), ``_host`` may be empty, which raises
    ``"server_hostname cannot be empty"`` on Python ≥ 3.13.

    :param smtp: SMTP client instance whose ``_host`` attribute will be set.
    :type smtp: smtplib.SMTP
    :param sni_hostname: Hostname to use for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param fallback: Value to use when *sni_hostname* is ``None``.
    :type fallback: str
    """
    smtp._host = sni_hostname if sni_hostname else fallback  # type: ignore[attr-defined]


def _starttls_and_get_cipher(
    host: str,
    port: int,
    helo_domain: str,
    sni_hostname: str | None,
    ctx: ssl.SSLContext,
) -> str | None:  # pragma: no cover
    """Perform a STARTTLS handshake with *ctx* and return the negotiated cipher name.

    Opens a fresh connection for each call.  Cleans up the socket whether or
    not the handshake succeeds.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port.
    :type port: int
    :param helo_domain: Domain name to send in the EHLO command.
    :type helo_domain: str
    :param sni_hostname: Hostname for SNI, or ``None`` for bare IPs.
    :type sni_hostname: str or None
    :param ctx: Pre-configured :class:`ssl.SSLContext` to use for the handshake.
    :type ctx: ssl.SSLContext
    :returns: Negotiated cipher name, or ``None`` on any failure
        (connection refused, STARTTLS absent, SSL error).
    :rtype: str or None
    """
    try:
        smtp, _, _ = _connect_plain(host, port)
    except (OSError, smtplib.SMTPException):
        return None
    try:
        smtp.ehlo(helo_domain)
        if not smtp.has_extn("STARTTLS"):
            smtp.quit()
            return None
        _set_sni(smtp, sni_hostname, host)
        smtp.starttls(context=ctx)
        info = smtp.sock.cipher()  # type: ignore[union-attr]
        smtp.quit()
        return info[0] if info else None
    except Exception:
        try:
            smtp.close()
        except Exception:
            pass
        return None
