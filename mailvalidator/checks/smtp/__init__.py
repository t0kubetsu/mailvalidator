"""SMTP diagnostics package.

Re-exports the public API and all private helpers required by the test suite
so that ``from mailvalidator.checks.smtp import <name>`` continues to work
after the module was split into sub-modules.
"""

from __future__ import annotations

# Public entry point
from ._check import _connect_or_fallback, _SMTP_FALLBACK_PORTS, check_smtp

# _cert
from ._cert import _cert_info, _check_certificate

# _classify
from ._classify import _classify_cipher, _classify_ec_curve, _tls_version_status

# _connection
from ._connection import _is_ip, _no_verify_ctx, _set_sni

# _dns
from ._dns import (
    _check_caa,
    _check_dane,
    _fetch_cert_der,
    _parse_caa_record,
    _tlsa_fingerprint,
    _verify_tlsa_record,
)

# resolve — re-exported so patch("mailvalidator.checks.smtp.resolve", …) works
from mailvalidator.dns_utils import resolve

# _protocol
from ._protocol import (
    _check_banner_fqdn,
    _check_ehlo_domain,
    _check_extensions,
)

# _pqc
from ._pqc import _assess_pqc, _check_pqc

# _tls_checks
from ._tls_checks import (
    _check_cipher,
    _check_cipher_order,
    _check_compression,
    _check_hash_function,
    _check_key_exchange,
    _check_renegotiation,
    _check_tls_version,
)

# _tls_probe — also re-exported so mock patch paths resolve against this namespace
from ._tls_probe import (
    _detect_server_cipher_order,
    _enumerate_ciphers_for_version,
    _make_cipher_probe_ctx,
    _probe_single_tls_version,
)

__all__ = [
    "check_smtp",
    "_assess_pqc",
    "_check_pqc",
    "_connect_or_fallback",
    "_SMTP_FALLBACK_PORTS",
    "_cert_info",
    "_check_banner_fqdn",
    "_check_caa",
    "_check_certificate",
    "_check_cipher",
    "_check_cipher_order",
    "_check_compression",
    "_check_dane",
    "_check_ehlo_domain",
    "_check_extensions",
    "_check_hash_function",
    "_check_key_exchange",
    "_check_renegotiation",
    "_check_tls_version",
    "_classify_cipher",
    "_classify_ec_curve",
    "_detect_server_cipher_order",
    "_enumerate_ciphers_for_version",
    "_is_ip",
    "_make_cipher_probe_ctx",
    "_no_verify_ctx",

    "_fetch_cert_der",
    "_parse_caa_record",
    "_probe_single_tls_version",
    "_set_sni",
    "_tls_version_status",
    "_tlsa_fingerprint",
    "_verify_tlsa_record",
    "resolve",
]
