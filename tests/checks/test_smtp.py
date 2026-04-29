"""Tests for mailvalidator/checks/smtp.py – pure-logic checks only.

Network I/O functions (_probe_tls, check_smtp, etc.) require a live SMTP
server and are covered by integration tests only.
"""

from __future__ import annotations

import datetime as _dt
import smtplib
import ssl
from unittest.mock import MagicMock, patch

import pytest

from mailvalidator.checks.smtp import (
    _connect_or_fallback,
    _cert_info,
    _check_banner_fqdn,
    _check_caa,
    _check_certificate,
    _check_cipher,
    _check_cipher_order,
    _check_compression,
    _check_dane,
    _check_ehlo_domain,
    _check_extensions,
    _check_hash_function,
    _check_key_exchange,
    _check_renegotiation,
    _check_tls_version,
    _classify_cipher,
    _classify_ec_curve,
    _is_ip,
    _make_cipher_probe_ctx,
    _no_verify_ctx,
    _set_sni,
    _tls_version_status,
    _tlsa_fingerprint,
    _verify_tlsa_record,
)
from mailvalidator.models import Status
from tests.conftest import make_tls

# ── SMTP TLS checks ───────────────────────────────────────────────────────────


class TestTLSVersion:
    def test_tls13_ok(self):
        assert _tls_version_status("TLSv1.3") == Status.OK

    def test_tls12_sufficient(self):
        assert _tls_version_status("TLSv1.2") == Status.SUFFICIENT

    def test_tls11_phase_out(self):
        assert _tls_version_status("TLSv1.1") == Status.PHASE_OUT

    def test_tls10_phase_out(self):
        assert _tls_version_status("TLSv1") == Status.PHASE_OUT

    def test_ssl3_insufficient(self):
        assert _tls_version_status("SSLv3") == Status.INSUFFICIENT

    def test_check_emits_result_good(self):
        """TLS 1.3 accepted, older versions rejected → GOOD verdict."""
        checks: list = []
        # TLS 1.3 accepted, TLS 1.2 rejected → best negotiated 1.3, overall GOOD
        with patch(
            "mailvalidator.checks.smtp._probe_single_tls_version",
            side_effect=lambda h, p, helo, sni, tls_min, tls_max: (
                tls_min == ssl.TLSVersion.TLSv1_3
            ),
        ):
            _check_tls_version(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                make_tls(tls_version="TLSv1.3"),
                checks,
            )
        assert checks[0].status == Status.GOOD

    def test_check_phase_out_when_old_tls_accepted(self):
        """Accepting TLS 1.1 (phase-out) should produce a PHASE_OUT verdict."""
        checks: list = []

        # tls_min is the 5th positional arg (index 4); accept only TLS 1.1
        tls11 = getattr(ssl.TLSVersion, "TLSv1_1", None)

        def _accept_tls11_only(h, p, helo, sni, tls_min, tls_max):
            return tls_min == tls11

        if tls11 is None:
            pytest.skip("TLSv1_1 not available on this OpenSSL build")

        with patch(
            "mailvalidator.checks.smtp._probe_single_tls_version",
            side_effect=_accept_tls11_only,
        ):
            _check_tls_version(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                make_tls(tls_version="TLSv1.1"),
                checks,
            )
        assert checks[0].status in (Status.PHASE_OUT, Status.INSUFFICIENT)


class TestCipherClassification:
    def test_good_cipher(self):
        assert _classify_cipher("ECDHE-RSA-AES256-GCM-SHA384") == Status.GOOD

    def test_good_tls13_cipher(self):
        assert _classify_cipher("TLS_AES_256_GCM_SHA384") == Status.GOOD

    def test_sufficient_cipher(self):
        assert _classify_cipher("DHE-RSA-AES256-SHA256") == Status.SUFFICIENT

    def test_phase_out_cipher(self):
        assert _classify_cipher("AES256-SHA") == Status.PHASE_OUT

    def test_unknown_cipher_insufficient(self):
        assert _classify_cipher("RC4-MD5") == Status.INSUFFICIENT

    def test_check_emits_per_version_results(self):
        """_check_cipher should emit one CheckResult per TLS version found."""
        checks: list = []
        tls = make_tls()
        # Simulate enumeration returning ciphers for TLS 1.3 only
        with patch(
            "mailvalidator.checks.smtp._enumerate_ciphers_for_version",
            side_effect=lambda h, p, helo, sni, mn, mx, **kw: (
                ["TLS_AES_256_GCM_SHA384"] if mn == ssl.TLSVersion.TLSv1_3 else []
            ),
        ):
            _check_cipher(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                tls,
                checks,
            )
        assert any("TLSv1.3" in c.name for c in checks)
        assert all(
            c.status
            in (Status.GOOD, Status.SUFFICIENT, Status.PHASE_OUT, Status.INSUFFICIENT)
            for c in checks
            if "Cipher" in c.name
        )


class TestCipherOrder:
    def _tls(self, ciphers_by_version: dict) -> object:
        tls = make_tls()
        tls.offered_ciphers_by_version = ciphers_by_version
        return tls

    def test_good_only_is_na(self):
        checks: list = []
        tls = self._tls(
            {"TLSv1.3": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]}
        )
        with patch(
            "mailvalidator.checks.smtp._detect_server_cipher_order", return_value=True
        ):
            _check_cipher_order(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                tls,
                checks,
            )
        assert any(c.status == Status.NA for c in checks)

    def test_correct_ordering(self):
        checks: list = []
        tls = self._tls(
            {
                "TLSv1.2": [
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "DHE-RSA-AES256-SHA256",
                    "AES256-SHA",
                ]
            }
        )
        with patch(
            "mailvalidator.checks.smtp._detect_server_cipher_order", return_value=True
        ):
            _check_cipher_order(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                tls,
                checks,
            )
        order_checks = [c for c in checks if "Prescribed" in c.name]
        assert order_checks[0].status == Status.OK

    def test_wrong_ordering(self):
        checks: list = []
        # Phase-out before Good is wrong order
        tls = self._tls({"TLSv1.2": ["AES256-SHA", "ECDHE-RSA-AES256-GCM-SHA384"]})
        with patch(
            "mailvalidator.checks.smtp._detect_server_cipher_order", return_value=True
        ):
            _check_cipher_order(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                tls,
                checks,
            )
        order_checks = [c for c in checks if "Prescribed" in c.name]
        assert order_checks[0].status == Status.WARNING


class TestKeyExchange:
    def test_good_ec_curve(self):
        assert _classify_ec_curve("secp256r1") == Status.GOOD
        assert _classify_ec_curve("x25519") == Status.GOOD

    def test_phase_out_curve(self):
        assert _classify_ec_curve("secp224r1") == Status.PHASE_OUT

    def test_insufficient_curve(self):
        assert _classify_ec_curve("sect163k1") == Status.INSUFFICIENT

    def test_ecdhe_check(self):
        checks: list = []
        tls = make_tls(cipher_name="ECDHE-RSA-AES256-GCM-SHA384", dh_group="secp256r1")
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.GOOD

    def test_dhe_sufficient(self):
        checks: list = []
        tls = make_tls(
            cipher_name="DHE-RSA-AES256-GCM-SHA384", dh_bits=3072, tls_version="TLSv1.2"
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.SUFFICIENT

    def test_dhe_phase_out(self):
        checks: list = []
        tls = make_tls(
            cipher_name="DHE-RSA-AES256-GCM-SHA384", dh_bits=2048, tls_version="TLSv1.2"
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.PHASE_OUT


class TestHashFunction:
    def test_tls13_always_good(self):
        checks: list = []
        _check_hash_function(make_tls(tls_version="TLSv1.3"), checks)
        assert checks[0].status == Status.GOOD

    def test_sha384_good(self):
        checks: list = []
        _check_hash_function(
            make_tls(tls_version="TLSv1.2", cipher_name="ECDHE-RSA-AES256-GCM-SHA384"),
            checks,
        )
        assert checks[0].status == Status.GOOD

    def test_sha1_phase_out(self):
        checks: list = []
        _check_hash_function(
            make_tls(tls_version="TLSv1.2", cipher_name="ECDHE-RSA-AES128-SHA"), checks
        )
        assert checks[0].status == Status.PHASE_OUT


class TestCompression:
    def test_no_compression_good(self):
        checks: list = []
        _check_compression(make_tls(compression=""), checks)
        assert checks[0].status == Status.GOOD

    def test_deflate_insufficient(self):
        checks: list = []
        _check_compression(make_tls(compression="deflate"), checks)
        assert checks[0].status == Status.INSUFFICIENT


class TestDANE:
    """Tests for DANE TLSA fingerprint verification."""

    def _make_self_signed_der(self) -> bytes:
        """Generate a minimal self-signed cert DER for testing."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_fingerprint_sha256_cert(self):
        import hashlib

        der = self._make_self_signed_der()
        expected = hashlib.sha256(der).hexdigest()
        result = _tlsa_fingerprint(der, selector=0, matching=1)
        assert result == expected

    def test_fingerprint_sha256_spki(self):
        import hashlib

        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        der = self._make_self_signed_der()
        cert = x509.load_der_x509_certificate(der)
        spki = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        expected = hashlib.sha256(spki).hexdigest()
        result = _tlsa_fingerprint(der, selector=1, matching=1)
        assert result == expected

    def test_fingerprint_sha512_cert(self):
        import hashlib

        der = self._make_self_signed_der()
        expected = hashlib.sha512(der).hexdigest()
        result = _tlsa_fingerprint(der, selector=0, matching=2)
        assert result == expected

    def test_verify_tlsa_match(self):
        import hashlib

        der = self._make_self_signed_der()
        fp = hashlib.sha256(der).hexdigest()
        record = f"3 0 1 {fp}"
        ok, desc = _verify_tlsa_record(record, der)
        assert ok is True
        assert "matches" in desc

    def test_verify_tlsa_mismatch(self):
        der = self._make_self_signed_der()
        record = "3 0 1 " + "00" * 32  # wrong fingerprint
        ok, desc = _verify_tlsa_record(record, der)
        assert ok is False
        assert "MISMATCH" in desc

    def test_check_dane_no_records(self):
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[]):
            _check_dane(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                None,
                checks,
            )
        assert checks[0].status == Status.INFO
        assert "not configured" in checks[0].details[0]

    def test_check_dane_match(self):
        import hashlib

        der = self._make_self_signed_der()
        fp = hashlib.sha256(der).hexdigest()
        record = f"3 0 1 {fp}"
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                der,
                checks,
            )
        match_check = next(c for c in checks if "Match" in c.name)
        assert match_check.status == Status.OK

    def test_check_dane_mismatch(self):
        der = self._make_self_signed_der()
        record = "3 0 1 " + "ab" * 32  # wrong fingerprint
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                der,
                checks,
            )
        match_check = next(c for c in checks if "Match" in c.name)
        assert match_check.status == Status.ERROR

    def test_check_dane_rollover(self):
        """One matching record (current) + one non-matching (next) should be OK."""
        import hashlib

        der = self._make_self_signed_der()
        fp = hashlib.sha256(der).hexdigest()
        current_record = f"3 0 1 {fp}"
        next_record = "3 0 1 " + "cc" * 32  # pre-published for next cert
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=[current_record, next_record],
        ):
            _check_dane(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                der,
                checks,
            )
        match_check = next(c for c in checks if "Match" in c.name)
        assert match_check.status == Status.OK
        assert "pre-published" in " ".join(match_check.details)

    def test_check_dane_pkix_only(self):
        """PKIX-TA(0) and PKIX-EE(1) records should warn, not count as valid."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=["0 0 1 " + "aa" * 32, "1 0 1 " + "bb" * 32],
        ):
            _check_dane(
                "mail.example.com",
                25,
                "mailvalidator.local",
                "mail.example.com",
                None,
                checks,
            )
        exist_check = next(c for c in checks if "Existence" in c.name)
        assert exist_check.status == Status.WARNING


# ── BIMI (additional coverage) ───────────────────────────────────────────────


class TestClassifyEcCurveExtra:
    def test_empty_string_returns_info(self):
        assert _classify_ec_curve("") == Status.INFO


# ── _cert_info ────────────────────────────────────────────────────────────────


class TestCertInfo:
    """Tests for the DER certificate parser."""

    def _make_rsa_cert_der(self, key_size: int = 2048) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def _make_ec_cert_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def _make_rsa_cert_with_san_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "san.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("san.example.com")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_rsa_cert_parsed(self):
        der = self._make_rsa_cert_der()
        info = _cert_info(der)
        assert info["pubkey_type"] == "RSA"
        assert info["pubkey_bits"] == 2048
        assert "CN=test.example.com" in info["subject"]

    def test_ec_cert_parsed(self):
        der = self._make_ec_cert_der()
        info = _cert_info(der)
        assert info["pubkey_type"] == "EC"
        assert info["pubkey_curve"] == "secp256r1"

    def test_san_extracted(self):
        der = self._make_rsa_cert_with_san_der()
        info = _cert_info(der)
        assert "san.example.com" in info["san"]

    def test_no_san_returns_empty_list(self):
        der = self._make_rsa_cert_der()
        info = _cert_info(der)
        assert info["san"] == []

    def test_invalid_der_returns_empty_dict(self):
        assert _cert_info(b"not a cert") == {}


# ── _is_ip ────────────────────────────────────────────────────────────────────


class TestIsIp:
    def test_ipv4_returns_true(self):
        assert _is_ip("1.2.3.4") is True

    def test_ipv6_returns_true(self):
        assert _is_ip("2001:db8::1") is True

    def test_hostname_returns_false(self):
        assert _is_ip("mail.example.com") is False

    def test_empty_string_returns_false(self):
        assert _is_ip("") is False


# ── _no_verify_ctx ────────────────────────────────────────────────────────────


class TestNoVerifyCtx:
    def test_returns_ssl_context(self):
        ctx = _no_verify_ctx()
        assert isinstance(ctx, ssl.SSLContext)

    def test_check_hostname_disabled(self):
        ctx = _no_verify_ctx()
        assert ctx.check_hostname is False

    def test_verify_mode_is_none(self):
        ctx = _no_verify_ctx()
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_version_range_applied(self):
        ctx = _no_verify_ctx(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2


# ── _set_sni ──────────────────────────────────────────────────────────────────


class TestSetSni:
    def test_uses_sni_hostname_when_provided(self):
        smtp = MagicMock(spec=smtplib.SMTP)
        _set_sni(smtp, "mail.example.com", "fallback.example.com")
        assert smtp._host == "mail.example.com"

    def test_uses_fallback_when_sni_is_none(self):
        smtp = MagicMock(spec=smtplib.SMTP)
        _set_sni(smtp, None, "fallback.example.com")
        assert smtp._host == "fallback.example.com"


# ── _make_cipher_probe_ctx ────────────────────────────────────────────────────


class TestMakeCipherProbeCtx:
    def test_tls13_ctx_no_cipher_call(self):
        """For TLS 1.3 the cipher list is not touched; only the version is pinned."""
        ctx = _make_cipher_probe_ctx(
            "TLS_AES_256_GCM_SHA384",
            ssl.TLSVersion.TLSv1_3,
            ssl.TLSVersion.TLSv1_3,
        )
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3

    def test_tls12_ctx_sets_cipher(self):
        """For TLS 1.2 the cipher is restricted via set_ciphers()."""
        ctx = _make_cipher_probe_ctx(
            "ECDHE-RSA-AES256-GCM-SHA384",
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_2,
        )
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_seclevel0_appended_when_requested(self):
        """seclevel0=True must not raise for a known cipher."""
        ctx = _make_cipher_probe_ctx(
            "DHE-RSA-AES256-SHA",
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_2,
            seclevel0=True,
        )
        assert isinstance(ctx, ssl.SSLContext)

    def test_unknown_cipher_raises_ssl_error(self):
        """An unrecognised cipher name should raise ssl.SSLError."""
        with pytest.raises(ssl.SSLError):
            _make_cipher_probe_ctx(
                "NOT-A-REAL-CIPHER",
                ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.TLSv1_2,
            )


# ── _check_tls_version: remaining branches ───────────────────────────────────


class TestCheckTlsVersionExtra:
    def test_insufficient_version_accepted(self):
        """An accepted version classified INSUFFICIENT → overall INSUFFICIENT."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp._probe_single_tls_version", return_value=True
        ):
            with patch(
                "mailvalidator.checks.smtp._tls_version_status",
                return_value=Status.INSUFFICIENT,
            ):
                _check_tls_version(
                    "mail.example.com",
                    25,
                    "mailvalidator.local",
                    None,
                    make_tls(tls_version="SSLv3"),
                    checks,
                )
        assert checks[0].status == Status.INSUFFICIENT

    def test_only_sufficient_version_accepted(self):
        """Only TLS 1.2 accepted (SUFFICIENT) and no GOOD → SUFFICIENT overall."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp._probe_single_tls_version",
            side_effect=lambda h, p, helo, sni, mn, mx: mn == ssl.TLSVersion.TLSv1_2,
        ):
            _check_tls_version(
                "mail.example.com",
                25,
                "mailvalidator.local",
                None,
                make_tls(tls_version="TLSv1.2"),
                checks,
            )
        assert checks[0].status == Status.SUFFICIENT

    def test_all_probes_fail_returns_info(self):
        """All probes failing (server unreachable) → INFO status."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp._probe_single_tls_version", return_value=False
        ):
            _check_tls_version(
                "mail.example.com",
                25,
                "mailvalidator.local",
                None,
                make_tls(tls_version=""),
                checks,
            )
        assert checks[0].status == Status.INFO


# ── _check_cipher: worst-status bubbling ─────────────────────────────────────


class TestCheckCipherExtra:
    def test_worst_status_bubbles_up(self):
        """When mix of Good and Phase-out ciphers, ver_worst should be PHASE_OUT."""
        checks: list = []
        tls = make_tls()
        mixed = ["ECDHE-RSA-AES256-GCM-SHA384", "AES256-SHA"]  # Good + Phase-out
        with patch(
            "mailvalidator.checks.smtp._enumerate_ciphers_for_version",
            side_effect=lambda h, p, helo, sni, mn, mx, **kw: (
                mixed if mn == ssl.TLSVersion.TLSv1_2 else []
            ),
        ):
            _check_cipher(
                "mail.example.com", 25, "mailvalidator.local", None, tls, checks
            )
        cipher_check = next(c for c in checks if "TLSv1.2" in c.name)
        assert cipher_check.status == Status.PHASE_OUT

    def test_phase_out_appends_summary_line(self):
        """When PHASE_OUT ciphers are present, a summary line is appended to details."""
        checks: list = []
        tls = make_tls()
        mixed = ["ECDHE-RSA-AES256-GCM-SHA384", "AES256-SHA"]  # Good + Phase-out
        with patch(
            "mailvalidator.checks.smtp._enumerate_ciphers_for_version",
            side_effect=lambda h, p, helo, sni, mn, mx, **kw: (
                mixed if mn == ssl.TLSVersion.TLSv1_2 else []
            ),
        ):
            _check_cipher(
                "mail.example.com", 25, "mailvalidator.local", None, tls, checks
            )
        cipher_check = next(c for c in checks if "TLSv1.2" in c.name)
        assert cipher_check.details[-1].startswith("Remove phase-out cipher(s):")
        assert "AES256-SHA" in cipher_check.details[-1]

    def test_all_good_ciphers_no_summary_line(self):
        """When all ciphers are GOOD, no summary line is appended."""
        checks: list = []
        tls = make_tls()
        good_only = ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"]
        with patch(
            "mailvalidator.checks.smtp._enumerate_ciphers_for_version",
            side_effect=lambda h, p, helo, sni, mn, mx, **kw: (
                good_only if mn == ssl.TLSVersion.TLSv1_2 else []
            ),
        ):
            _check_cipher(
                "mail.example.com", 25, "mailvalidator.local", None, tls, checks
            )
        cipher_check = next(c for c in checks if "TLSv1.2" in c.name)
        assert cipher_check.status == Status.GOOD
        assert not any("Remove phase-out" in d for d in cipher_check.details)


# ── _check_cipher_order: no-data branch ──────────────────────────────────────


class TestCheckCipherOrderExtra:
    def test_no_data_emits_info(self):
        """When offered_ciphers_by_version is empty, emit a single INFO result."""
        checks: list = []
        tls = make_tls()
        tls.offered_ciphers_by_version = {}
        _check_cipher_order(
            "mail.example.com", 25, "mailvalidator.local", None, tls, checks
        )
        assert len(checks) == 1
        assert checks[0].status == Status.INFO

    def test_not_enforced_produces_warning(self):
        """Server not enforcing order → WARNING for server preference."""
        checks: list = []
        tls = make_tls()
        tls.offered_ciphers_by_version = {
            "TLSv1.2": ["ECDHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES256-SHA256"]
        }
        with patch(
            "mailvalidator.checks.smtp._detect_server_cipher_order", return_value=False
        ):
            _check_cipher_order(
                "mail.example.com", 25, "mailvalidator.local", None, tls, checks
            )
        pref = next(c for c in checks if "Server Preference" in c.name)
        assert pref.status == Status.WARNING

    def test_cannot_determine_order_emits_info(self):
        """_detect_server_cipher_order returning None → INFO."""
        checks: list = []
        tls = make_tls()
        tls.offered_ciphers_by_version = {"TLSv1.2": ["ECDHE-RSA-AES256-GCM-SHA384"]}
        with patch(
            "mailvalidator.checks.smtp._detect_server_cipher_order", return_value=None
        ):
            _check_cipher_order(
                "mail.example.com", 25, "mailvalidator.local", None, tls, checks
            )
        pref = next(c for c in checks if "Server Preference" in c.name)
        assert pref.status == Status.INFO


# ── _check_key_exchange: remaining branches ──────────────────────────────────


class TestCheckKeyExchangeExtra:
    def test_tls13_with_known_group(self):
        """TLS 1.3 with dh_group populated → classified by curve."""
        checks: list = []
        tls = make_tls(
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            dh_group="x25519",
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.GOOD
        assert "x25519" in checks[0].value

    def test_tls13_with_phase_out_group(self):
        """TLS 1.3 with a deprecated curve → PHASE_OUT."""
        checks: list = []
        tls = make_tls(
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            dh_group="secp224r1",
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.PHASE_OUT

    def test_tls13_without_group(self):
        """TLS 1.3 with no dh_group → GOOD with informational note."""
        checks: list = []
        tls = make_tls(
            tls_version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384", dh_group=""
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.GOOD

    def test_dhe_insufficient_bits(self):
        """DHE with <2048 bits → INSUFFICIENT."""
        checks: list = []
        tls = make_tls(
            cipher_name="DHE-RSA-AES256-GCM-SHA384", dh_bits=1024, tls_version="TLSv1.2"
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.INSUFFICIENT

    def test_dhe_unknown_bits(self):
        """DHE with dh_bits=0 → INFO."""
        checks: list = []
        tls = make_tls(
            cipher_name="DHE-RSA-AES256-GCM-SHA384", dh_bits=0, tls_version="TLSv1.2"
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.INFO

    def test_rsa_kex_phase_out(self):
        """Static RSA key exchange → PHASE_OUT."""
        checks: list = []
        tls = make_tls(cipher_name="AES256-SHA", tls_version="TLSv1.2")
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.PHASE_OUT
        assert checks[0].name == "Key Exchange"

    def test_ecdhe_phase_out_curve(self):
        """ECDHE-* with a deprecated curve → PHASE_OUT."""
        checks: list = []
        tls = make_tls(
            cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
            dh_group="secp224r1",
            tls_version="TLSv1.2",
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.PHASE_OUT

    def test_ecdhe_insufficient_curve(self):
        """ECDHE-* with an unknown/insecure curve → INSUFFICIENT."""
        checks: list = []
        tls = make_tls(
            cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
            dh_group="sect163k1",
            tls_version="TLSv1.2",
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.INSUFFICIENT

    def test_ecdhe_no_group_info(self):
        """ECDHE-* with empty dh_group → INFO (curve not exposed)."""
        checks: list = []
        tls = make_tls(
            cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
            dh_group="",
            tls_version="TLSv1.2",
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.INFO


# ── _check_hash_function: remaining branches ─────────────────────────────────


class TestCheckHashFunctionExtra:
    def test_hash_not_in_cipher_returns_info(self):
        """Cipher name with no recognisable hash suffix → INFO."""
        checks: list = []
        _check_hash_function(
            make_tls(tls_version="TLSv1.2", cipher_name="SOME-UNKNOWN-CIPHER"),
            checks,
        )
        assert checks[0].status == Status.INFO


# ── _check_compression: remaining branch ─────────────────────────────────────


class TestCheckCompressionExtra:
    def test_app_level_compression_sufficient(self):
        """An unknown compression value (app-level) → SUFFICIENT."""
        checks: list = []
        _check_compression(make_tls(compression="lz4"), checks)
        assert checks[0].status == Status.SUFFICIENT


# ── _check_renegotiation: all branches ───────────────────────────────────────


class TestCheckRenegotiationExtra:
    def test_tls13_both_na(self):
        checks: list = []
        _check_renegotiation(make_tls(tls_version="TLSv1.3"), checks)
        assert all(c.status == Status.GOOD for c in checks)

    def test_secure_renegotiation_false(self):
        checks: list = []
        tls = make_tls(tls_version="TLSv1.2", secure_renegotiation=False)
        _check_renegotiation(tls, checks)
        sr = next(c for c in checks if c.name == "Secure Renegotiation")
        assert sr.status == Status.INSUFFICIENT

    def test_secure_renegotiation_unknown(self):
        checks: list = []
        tls = make_tls(tls_version="TLSv1.2", secure_renegotiation=None)
        _check_renegotiation(tls, checks)
        sr = next(c for c in checks if c.name == "Secure Renegotiation")
        assert sr.status == Status.INFO

    def test_client_initiated_always_info_for_tls12(self):
        checks: list = []
        tls = make_tls(tls_version="TLSv1.2", secure_renegotiation=True)
        _check_renegotiation(tls, checks)
        ci = next(c for c in checks if c.name == "Client-Initiated Renegotiation")
        assert ci.status == Status.INFO


# ── _check_certificate: all branches ─────────────────────────────────────────


class TestCheckCertificateExtra:
    """Test _check_certificate with pre-populated TLSDetails (no network)."""

    def _tls_with_cert(self, **kwargs) -> object:
        defaults = dict(
            cert_subject="CN=mail.example.com",
            cert_issuer="CN=Test CA",
            cert_san=["mail.example.com"],
            cert_not_after=(
                _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=90)
            ).isoformat(),
            cert_sig_alg="sha256",
            cert_pubkey_type="RSA",
            cert_pubkey_bits=2048,
            cert_pubkey_curve="",
            cert_trusted=True,
        )
        defaults.update(kwargs)
        return make_tls(**defaults)

    def test_no_subject_returns_info(self):
        checks: list = []
        _check_certificate(make_tls(cert_subject=""), checks, "mail.example.com")
        assert checks[0].status == Status.INFO

    def test_trusted_chain_good(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_trusted=True), checks, "mail.example.com"
        )
        trust = next(c for c in checks if c.name == "Certificate Trust Chain")
        assert trust.status == Status.GOOD

    def test_untrusted_chain_warning(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_trusted=False), checks, "mail.example.com"
        )
        trust = next(c for c in checks if c.name == "Certificate Trust Chain")
        assert trust.status == Status.WARNING

    def test_unknown_trust_info(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_trusted=None), checks, "mail.example.com"
        )
        trust = next(c for c in checks if c.name == "Certificate Trust Chain")
        assert trust.status == Status.INFO

    def test_rsa_3072_good(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_pubkey_type="RSA", cert_pubkey_bits=3072),
            checks,
            "mail.example.com",
        )
        pk = next(c for c in checks if c.name == "Certificate Public Key")
        assert pk.status == Status.GOOD

    def test_rsa_2048_sufficient(self):
        checks: list = []
        _check_certificate(self._tls_with_cert(), checks, "mail.example.com")
        pk = next(c for c in checks if c.name == "Certificate Public Key")
        assert pk.status == Status.SUFFICIENT

    def test_rsa_1024_insufficient(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_pubkey_bits=1024),
            checks,
            "mail.example.com",
        )
        pk = next(c for c in checks if c.name == "Certificate Public Key")
        assert pk.status == Status.INSUFFICIENT

    def test_ec_good_curve(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(
                cert_pubkey_type="EC",
                cert_pubkey_curve="secp256r1",
                cert_pubkey_bits=256,
            ),
            checks,
            "mail.example.com",
        )
        pk = next(c for c in checks if c.name == "Certificate Public Key")
        assert pk.status == Status.GOOD

    def test_ec_phase_out_curve(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(
                cert_pubkey_type="EC",
                cert_pubkey_curve="secp224r1",
                cert_pubkey_bits=224,
            ),
            checks,
            "mail.example.com",
        )
        pk = next(c for c in checks if c.name == "Certificate Public Key")
        assert pk.status == Status.PHASE_OUT

    def test_ec_insufficient_curve(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(
                cert_pubkey_type="EC",
                cert_pubkey_curve="sect163k1",
                cert_pubkey_bits=163,
            ),
            checks,
            "mail.example.com",
        )
        pk = next(c for c in checks if c.name == "Certificate Public Key")
        assert pk.status == Status.INSUFFICIENT

    def test_unknown_pubkey_type_info(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_pubkey_type="DSA"),
            checks,
            "mail.example.com",
        )
        pk = next(c for c in checks if c.name == "Certificate Public Key")
        assert pk.status == Status.INFO

    def test_sha1_sig_insufficient(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_sig_alg="sha1WithRSAEncryption"),
            checks,
            "mail.example.com",
        )
        sig = next(c for c in checks if c.name == "Certificate Signature")
        assert sig.status == Status.INSUFFICIENT

    def test_unknown_sig_info(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_sig_alg="unknownAlg"),
            checks,
            "mail.example.com",
        )
        sig = next(c for c in checks if c.name == "Certificate Signature")
        assert sig.status == Status.INFO

    def test_san_match(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_san=["mail.example.com"]),
            checks,
            "mail.example.com",
        )
        dm = next(c for c in checks if c.name == "Certificate Domain Match")
        assert dm.status == Status.OK

    def test_wildcard_san_match(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_san=["*.example.com"]),
            checks,
            "mail.example.com",
        )
        dm = next(c for c in checks if c.name == "Certificate Domain Match")
        assert dm.status == Status.OK

    def test_san_mismatch(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_san=["other.example.com"]),
            checks,
            "mail.example.com",
        )
        dm = next(c for c in checks if c.name == "Certificate Domain Match")
        assert dm.status == Status.WARNING

    def test_cn_fallback_when_no_san(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_san=[], cert_subject="CN=mail.example.com"),
            checks,
            "mail.example.com",
        )
        dm = next(c for c in checks if c.name == "Certificate Domain Match")
        assert dm.status == Status.OK

    def test_expired_cert(self):
        checks: list = []
        past = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1)).isoformat()
        _check_certificate(
            self._tls_with_cert(cert_not_after=past),
            checks,
            "mail.example.com",
        )
        exp = next(c for c in checks if c.name == "Certificate Expiry")
        assert exp.status == Status.ERROR

    def test_expiring_soon_warning(self):
        checks: list = []
        soon = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=15)).isoformat()
        _check_certificate(
            self._tls_with_cert(cert_not_after=soon),
            checks,
            "mail.example.com",
        )
        exp = next(c for c in checks if c.name == "Certificate Expiry")
        assert exp.status == Status.WARNING

    def test_invalid_date_returns_info(self):
        checks: list = []
        _check_certificate(
            self._tls_with_cert(cert_not_after="not-a-date"),
            checks,
            "mail.example.com",
        )
        exp = next(c for c in checks if c.name == "Certificate Expiry")
        assert exp.status == Status.INFO


# ── _check_caa ────────────────────────────────────────────────────────────────


class TestCheckCaaExtra:
    def test_no_caa_records_warns(self):
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[]):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.WARNING

    def test_valid_caa_ok(self):
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.OK

    def test_caa_found_on_parent_domain(self):
        """CAA walk should try parent labels if subdomain has none."""
        checks: list = []
        call_args = []

        def _fake_resolve(name, rdtype):
            call_args.append(name)
            if name == "example.com":
                return ['0 issue "letsencrypt.org"']
            return []

        with patch("mailvalidator.checks.smtp.resolve", side_effect=_fake_resolve):
            _check_caa("mail.example.com", checks)
        assert "example.com" in call_args
        assert checks[0].status == Status.OK

    def test_missing_issue_tag_warns(self):
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 iodef "mailto:ca@example.com"'],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.WARNING
        assert any("issue" in d for d in checks[0].details)

    def test_http_iodef_warns(self):
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=[
                '0 issue "letsencrypt.org"',
                '0 iodef "http://example.com/caa"',
            ],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.WARNING
        assert any("HTTP" in d or "http" in d for d in checks[0].details)

    def test_malformed_record_warns(self):
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issue "letsencrypt.org"', "badrecord"],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.WARNING


# ── _tlsa_fingerprint: remaining branches ────────────────────────────────────


class TestTlsaFingerprintExtra:
    def _make_cert_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_selector_0_matching_0_raw_hex(self):
        der = self._make_cert_der()
        result = _tlsa_fingerprint(der, selector=0, matching=0)
        assert result == der.hex()

    def test_unsupported_selector_returns_none(self):
        assert _tlsa_fingerprint(b"x", selector=99, matching=1) is None

    def test_unsupported_matching_returns_none(self):
        assert _tlsa_fingerprint(b"x", selector=0, matching=99) is None

    def test_invalid_der_returns_none(self):
        assert _tlsa_fingerprint(b"not a cert", selector=1, matching=1) is None


# ── _verify_tlsa_record: remaining branches ───────────────────────────────────


class TestVerifyTlsaRecordExtra:
    def _make_cert_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_malformed_record_too_few_parts(self):
        ok, desc = _verify_tlsa_record("3 0", b"x")
        assert ok is False
        assert "Malformed" in desc

    def test_non_integer_fields(self):
        ok, desc = _verify_tlsa_record("x y z abcdef", b"x")
        assert ok is False
        assert "parse" in desc.lower()

    def test_unsupported_fingerprint_type(self):
        der = self._make_cert_der()
        ok, desc = _verify_tlsa_record(f"3 99 1 {'aa' * 32}", der)
        assert ok is False
        assert "not supported" in desc

    def test_known_usage_names_in_label(self):
        import hashlib

        der = self._make_cert_der()
        fp = hashlib.sha256(der).hexdigest()
        ok, desc = _verify_tlsa_record(f"2 0 1 {fp}", der)
        assert ok is True
        assert "DANE-TA" in desc


# ── _check_dane: remaining branches ──────────────────────────────────────────


class TestCheckDaneExtra:
    def _make_cert_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_cert_der_none_and_no_fallback_warns(self):
        """No cert DER + _fetch_cert_der returning None → WARNING."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve", return_value=["3 0 1 " + "aa" * 32]
        ):
            with patch("mailvalidator.checks.smtp._fetch_cert_der", return_value=None):
                _check_dane(
                    "mail.example.com", 25, "mailvalidator.local", None, None, checks
                )
        match = next(c for c in checks if "Match" in c.name)
        assert match.status == Status.WARNING

    def test_nonstd_rollover_scheme_warns(self):
        """PKIX-TA + PKIX-EE mixed (non-standard) rollover → WARNING."""
        import hashlib

        der = self._make_cert_der()
        fp = hashlib.sha256(der).hexdigest()
        # Both usage 2, not a known good combination pattern (2+2 is OK, but 2 DANE-TA only)
        record1 = f"2 0 1 {fp}"
        record2 = "2 0 1 " + "cc" * 32  # non-matching DANE-TA
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve", return_value=[record1, record2]
        ):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, der, checks
            )
        rollover = next(c for c in checks if "Rollover" in c.name)
        # Two DANE-TA records without DANE-EE → non-standard
        assert rollover.status == Status.WARNING


# ── Targeted gap-fill tests ───────────────────────────────────────────────────


class TestCertInfoEdgeCases:
    def test_dsa_pubkey_type_reported(self):
        """A DSA public key (neither RSA nor EC) uses the generic type name."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.x509.oid import NameOID

        key = dsa.generate_private_key(key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dsa.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        info = _cert_info(der)
        assert info["pubkey_type"] == "DSAPublicKey"
        assert info["pubkey_bits"] == 0


class TestCheckCertificateNaiveDatetime:
    def test_naive_datetime_coerced_to_utc(self):
        """cert_not_after without tzinfo is treated as UTC (no crash)."""
        checks: list = []
        # ISO format without timezone offset → naive datetime
        future_naive = (
            _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=90)
        ).strftime("%Y-%m-%dT%H:%M:%S")
        tls = make_tls(
            cert_subject="CN=mail.example.com",
            cert_trusted=True,
            cert_san=["mail.example.com"],
            cert_sig_alg="sha256",
            cert_pubkey_type="RSA",
            cert_pubkey_bits=2048,
            cert_pubkey_curve="",
            cert_not_after=future_naive,
        )
        _check_certificate(tls, checks, "mail.example.com")
        exp = next(c for c in checks if c.name == "Certificate Expiry")
        assert exp.status == Status.OK


class TestCheckDaneEeEeRollover:
    def _make_cert_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_two_dane_ee_records_ok_rollover(self):
        """Two DANE-EE records (current + next cert) → OK rollover scheme."""
        import hashlib

        der = self._make_cert_der()
        fp = hashlib.sha256(der).hexdigest()
        record1 = f"3 0 1 {fp}"  # DANE-EE matching current cert
        record2 = "3 0 1 " + "dd" * 32  # DANE-EE pre-published for next cert
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve", return_value=[record1, record2]
        ):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, der, checks
            )
        rollover = next(c for c in checks if "Rollover" in c.name)
        assert rollover.status == Status.OK
        assert "EE + DANE-EE" in rollover.details[0]


# ── DANE-EE + DANE-TA rollover combination (smtp.py L1863) ────────


class TestCheckDaneEeTaRollover:
    def _make_cert_der(self) -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_dane_ee_plus_dane_ta_is_ok_rollover(self):
        """One DANE-EE (usage 3) + one DANE-TA (usage 2) → OK recommended rollover."""
        import hashlib

        der = self._make_cert_der()
        fp = hashlib.sha256(der).hexdigest()
        ee_record = f"3 0 1 {fp}"  # DANE-EE matching current cert
        ta_record = "2 0 1 " + "aa" * 32  # DANE-TA (issuer CA anchor)
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve", return_value=[ee_record, ta_record]
        ):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, der, checks
            )
        rollover = next(c for c in checks if "Rollover" in c.name)
        assert rollover.status == Status.OK
        assert "EE + DANE-TA" in rollover.details[0]


# ── CAA RFC-compliance tests (RFC 8659) ───────────────────────────────────────


class TestCheckCaaRfcCompliance:
    # C1: issuewild tag checked independently of issue
    def test_issuewild_present_without_issue_ok(self):
        """C1: An issuewild tag without an issue tag is valid for wildcard-only restriction."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issuewild "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status in (Status.OK, Status.WARNING)

    def test_issuewild_deny_all_flagged(self):
        """C1: issuewild \";\"/deny-all should be reported."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issue "letsencrypt.org"', '0 issuewild ";"'],
        ):
            _check_caa("mail.example.com", checks)
        assert any("issuewild" in d.lower() for d in checks[0].details)

    # C2: issue ";" (deny-all) distinguished from a named CA
    def test_issue_deny_all_reported(self):
        """C2: issue \";\" means no CA may issue non-wildcard certs; must be surfaced."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issue ";"'],
        ):
            _check_caa("mail.example.com", checks)
        assert any("deny-all" in d.lower() or '";' in d for d in checks[0].details)

    def test_named_issue_ca_ok(self):
        """C2: issue with a real CA name should NOT be treated as deny-all."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.OK

    # C3: No issuewild → note that issue governs wildcards too
    def test_no_issuewild_noted(self):
        """C3: When no issuewild is present, issue also governs wildcard issuance."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert any(
            "issuewild" in d.lower() or "wildcard" in d.lower()
            for d in checks[0].details
        )

    # C4: Flags byte validation
    def test_unexpected_flags_value_warns(self):
        """C4: A non-standard flags value should be reported."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['64 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert any("flags" in d.lower() or "64" in d for d in checks[0].details)

    def test_valid_flags_0_ok(self):
        """C4: Flags value 0 is standard and should not produce a detail warning."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['0 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert not any("unexpected flags" in d.lower() for d in checks[0].details)

    def test_critical_flags_128_ok(self):
        """C4: Flags value 128 (issuer critical) is defined by RFC 8659 and should be accepted."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['128 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert not any("unexpected flags" in d.lower() for d in checks[0].details)

    # C5: iodef scheme validation
    def test_iodef_http_warns(self):
        """C5: Plain HTTP in iodef URL should be flagged."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=[
                '0 issue "letsencrypt.org"',
                '0 iodef "http://example.com/caa"',
            ],
        ):
            _check_caa("mail.example.com", checks)
        assert any("http" in d.lower() for d in checks[0].details)
        assert checks[0].status == Status.WARNING

    def test_iodef_https_ok(self):
        """C5: HTTPS iodef URL should not trigger a warning."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=[
                '0 issue "letsencrypt.org"',
                '0 iodef "https://example.com/caa"',
            ],
        ):
            _check_caa("mail.example.com", checks)
        assert not any("unsupported scheme" in d.lower() for d in checks[0].details)

    def test_iodef_mailto_ok(self):
        """C5: mailto: iodef is valid per RFC 8659."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=[
                '0 issue "letsencrypt.org"',
                '0 iodef "mailto:ca@example.com"',
            ],
        ):
            _check_caa("mail.example.com", checks)
        assert not any("unsupported scheme" in d.lower() for d in checks[0].details)

    def test_iodef_ftp_warns(self):
        """C5: An ftp:// iodef URL uses an unsupported scheme."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=[
                '0 issue "letsencrypt.org"',
                '0 iodef "ftp://example.com/caa"',
            ],
        ):
            _check_caa("mail.example.com", checks)
        assert any("unsupported scheme" in d.lower() for d in checks[0].details)


# ── DANE RFC-compliance tests (RFC 6698, RFC 7671) ────────────────────────────


class TestCheckDaneRfcCompliance:
    def _make_cert_der(self) -> bytes:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    # D5: Matching type 0 (exact DER) is discouraged by RFC 7671 §5.1
    def test_matching_type_0_info_noted(self):
        """D5: A TLSA record with matching type 0 should carry an INFO note."""
        der = self._make_cert_der()
        record = f"3 0 0 {der.hex()}"
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, der, checks
            )
        assert any(
            c.name == "DANE – Matching Type" and c.status == Status.INFO for c in checks
        )

    def test_matching_type_1_no_info(self):
        """D5: Matching type 1 (SHA-256) is recommended and should not trigger D5 note."""
        import hashlib

        der = self._make_cert_der()
        fp = hashlib.sha256(der).hexdigest()
        record = f"3 0 1 {fp}"
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, der, checks
            )
        assert not any(c.name == "DANE – Matching Type" for c in checks)

    # D6: DNSSEC prerequisite WARNING always present when TLSA records exist
    def test_dnssec_prerequisite_warning_present(self):
        """D6: When TLSA records are found, a DNSSEC prerequisite WARNING must appear."""
        import hashlib

        der = self._make_cert_der()
        fp = hashlib.sha256(der).hexdigest()
        record = f"3 0 1 {fp}"
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, der, checks
            )
        assert any(
            c.name == "DANE – DNSSEC Prerequisite" and c.status == Status.WARNING
            for c in checks
        )

    def test_no_dnssec_note_when_dane_absent(self):
        """D6: When there are no TLSA records, no DNSSEC note should appear."""
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[]):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, None, checks
            )
        assert not any(c.name == "DANE – DNSSEC Prerequisite" for c in checks)


# ── RFC 5321 plain-SMTP checks ────────────────────────────────────────────────


class TestCheckBannerFqdn:
    """Tests for _check_banner_fqdn (RFC 5321 §4.1.3).

    The 220 greeting MUST include the server's FQDN (RFC 5321 §4.1.3).
    """

    def _run(self, banner: str) -> list:
        checks: list = []
        _check_banner_fqdn(banner, checks)
        return checks

    def test_valid_fqdn_ok(self):
        checks = self._run("220 mail.example.com ESMTP Postfix")
        assert checks[0].status == Status.OK
        assert checks[0].value == "mail.example.com"

    def test_fqdn_with_trailing_dot_ok(self):
        """A trailing dot is valid in DNS names."""
        checks = self._run("220 mail.example.com. ESMTP")
        assert checks[0].status == Status.OK

    def test_subdomain_ok(self):
        checks = self._run("220 mx1.mail.example.co.uk ESMTP")
        assert checks[0].status == Status.OK
        assert checks[0].value == "mx1.mail.example.co.uk"

    def test_220_prefix_stripped(self):
        """The '220 ' code prefix must be stripped before parsing the domain."""
        checks = self._run("220 smtp.example.org ESMTP ready")
        assert checks[0].value == "smtp.example.org"

    def test_bare_ipv4_warning(self):
        """RFC 5321 allows bare IPs but public MX servers should use a FQDN."""
        checks = self._run("220 203.0.113.42 ESMTP")
        assert checks[0].status == Status.WARNING
        assert "IP address" in checks[0].details[0]

    def test_ipv6_bracket_warning(self):
        checks = self._run("220 [2001:db8::1] ESMTP")
        assert checks[0].status == Status.WARNING

    def test_single_label_error(self):
        """A single-label name like 'mailserver' is not a valid FQDN."""
        checks = self._run("220 mailserver ESMTP")
        assert checks[0].status == Status.ERROR

    def test_empty_banner_error(self):
        checks = self._run("")
        assert checks[0].status == Status.ERROR

    def test_banner_code_only_error(self):
        """'220' with no following token must be flagged."""
        checks = self._run("220")
        assert checks[0].status == Status.ERROR

    def test_banner_without_220_prefix_valid_fqdn(self):
        """smtplib may strip the numeric code; bare FQDN should still pass."""
        checks = self._run("mail.example.com ESMTP Postfix")
        assert checks[0].status == Status.OK
        assert checks[0].value == "mail.example.com"


class TestCheckEhloDomain:
    """Tests for _check_ehlo_domain (RFC 5321 §4.1.1.1).

    The EHLO 250 response MUST include the server's FQDN on the first line.
    """

    def _make_smtp(self, ehlo_resp: bytes | None) -> object:
        smtp = MagicMock(spec=smtplib.SMTP)
        smtp.ehlo_resp = ehlo_resp
        return smtp

    def test_valid_fqdn_ok(self):
        smtp = self._make_smtp(b"250-mail.example.com\r\n250 STARTTLS")
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.OK
        assert checks[0].value == "mail.example.com"

    def test_250_space_format_ok(self):
        """Single-line EHLO response (250 <domain>) with no extensions."""
        smtp = self._make_smtp(b"250 smtp.example.org")
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.OK
        assert checks[0].value == "smtp.example.org"

    def test_domain_literal_warning(self):
        """[x.x.x.x] domain literal is RFC-conformant (§2.3.5) but unusual."""
        smtp = self._make_smtp(b"250-[203.0.113.1]\r\n250 STARTTLS")
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.WARNING
        assert "domain literal" in checks[0].details[0]

    def test_single_label_error(self):
        smtp = self._make_smtp(b"250 mailserver")
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.ERROR

    def test_no_ehlo_resp_warning(self):
        smtp = self._make_smtp(None)
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.WARNING

    def test_empty_ehlo_resp_warning(self):
        smtp = self._make_smtp(b"")
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status in (Status.WARNING, Status.ERROR)

    def test_subdomain_fqdn_ok(self):
        smtp = self._make_smtp(b"250-mx1.mail.example.co.uk\r\n250 STARTTLS")
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.OK
        assert checks[0].value == "mx1.mail.example.co.uk"

    def test_invalid_token_error(self):
        """A token that is neither an FQDN nor a domain literal must be flagged."""
        smtp = self._make_smtp(b"250 @invalid!")
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.ERROR


class TestCheckExtensions:
    """Tests for _check_extensions (RFC 1870, RFC 2920, RFC 6152, RFC 6531).

    ESMTP extension reporting is informational; absence of optional extensions
    is INFO, not WARNING/ERROR.
    """

    def _make_smtp(self, features: dict) -> object:
        smtp = MagicMock(spec=smtplib.SMTP)
        smtp.esmtp_features = {k.lower(): v for k, v in features.items()}
        smtp.has_extn = lambda ext: ext.upper() in {k.upper() for k in features}
        return smtp

    def test_all_extensions_present_ok(self):
        smtp = self._make_smtp(
            {"SIZE": "10240000", "PIPELINING": "", "8BITMIME": "", "SMTPUTF8": ""}
        )
        checks: list = []
        _check_extensions(smtp, checks)
        assert checks[0].status == Status.OK

    def test_some_missing_info(self):
        smtp = self._make_smtp({"SIZE": "10240000"})
        checks: list = []
        _check_extensions(smtp, checks)
        assert checks[0].status == Status.INFO
        assert "Not advertised" in checks[0].details[-1]

    def test_none_present_info(self):
        smtp = self._make_smtp({})
        checks: list = []
        _check_extensions(smtp, checks)
        assert checks[0].status == Status.INFO

    def test_size_value_included_in_details(self):
        """SIZE=<n> value should appear in the advertised detail line."""
        smtp = self._make_smtp(
            {"SIZE": "52428800", "PIPELINING": "", "8BITMIME": "", "SMTPUTF8": ""}
        )
        checks: list = []
        _check_extensions(smtp, checks)
        assert "52428800" in checks[0].details[0]

    def test_pipelining_advertised(self):
        smtp = self._make_smtp(
            {"PIPELINING": "", "SIZE": "", "8BITMIME": "", "SMTPUTF8": ""}
        )
        checks: list = []
        _check_extensions(smtp, checks)
        assert "PIPELINING" in checks[0].details[0]

    def test_result_value_shows_count(self):
        """The value field should report N of M extensions checked."""
        smtp = self._make_smtp({"SIZE": "", "PIPELINING": ""})
        checks: list = []
        _check_extensions(smtp, checks)
        assert "of 4" in checks[0].value


# ── _parse_caa_record (lines 1900-1909) ───────────────────────────────────────


class TestParseCaaRecord:
    """Direct unit tests for the _parse_caa_record helper."""

    def setup_method(self):
        from mailvalidator.checks.smtp import _parse_caa_record
        self._fn = _parse_caa_record

    def test_valid_record_parsed(self):
        result = self._fn('0 issue "letsencrypt.org"')
        assert result == (0, "issue", "letsencrypt.org")

    def test_too_few_parts_returns_none(self):
        assert self._fn("badrecord") is None

    def test_non_integer_flags_returns_none(self):
        assert self._fn('abc issue "letsencrypt.org"') is None


# ── _check_caa: uncovered branches (lines 1968-1970, 1987) ───────────────────


class TestCheckCaaUncoveredBranches:
    def test_non_integer_flags_treated_as_malformed(self):
        """Lines 1968-1970: a record with non-integer flags is appended to malformed."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['abc issue "letsencrypt.org"', '0 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.WARNING
        assert any("malformed" in d.lower() for d in checks[0].details)

    def test_critical_unrecognised_tag_warns(self):
        """Line 1987: flag 128 on an unknown tag must produce a WARNING."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=['128 unknowntag "value"', '0 issue "letsencrypt.org"'],
        ):
            _check_caa("mail.example.com", checks)
        assert checks[0].status == Status.WARNING
        assert any("Unrecognised critical tag" in d or "unrecognised critical tag" in d for d in checks[0].details)


# ── _check_dane: uncovered branches (lines 2272, 2299) ────────────────────────


class TestCheckDaneUncoveredBranches:
    def test_unknown_usage_type_skips_cert_verification(self):
        """Line 2272: when all TLSA records have usage ≥ 4, all_verifiable is
        empty and the function returns before fingerprint verification."""
        checks: list = []
        with patch(
            "mailvalidator.checks.smtp.resolve",
            return_value=["4 0 1 " + "aa" * 32],
        ):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, None, checks
            )
        assert not any("Match" in c.name for c in checks)

    def test_pkix_record_with_cert_gets_pkix_label(self):
        """Line 2299: a PKIX-EE(1) or PKIX-TA(0) record verified against a real
        cert gets a '[PKIX-constrained usage]' label in the Match check details."""
        import hashlib
        from tests.conftest import make_rsa_cert_der

        der = make_rsa_cert_der()
        fp = hashlib.sha256(der).hexdigest()
        record = f"1 0 1 {fp}"
        checks: list = []
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com", 25, "mailvalidator.local", None, der, checks
            )
        match_check = next((c for c in checks if "Match" in c.name), None)
        assert match_check is not None
        assert any("PKIX-constrained" in d for d in match_check.details)


# ── _check_ehlo_domain: empty domain_token (lines 2513-2520) ─────────────────


class TestCheckEhloDomainEmptyToken:
    def test_ehlo_resp_with_no_domain_token_errors(self):
        """Lines 2513-2520: an EHLO response whose first line is '250-' (no
        trailing domain) yields an empty token after stripping the prefix and
        must produce an ERROR check."""
        smtp = MagicMock(spec=smtplib.SMTP)
        smtp.ehlo_resp = b"250-\r\n250 STARTTLS"
        checks: list = []
        _check_ehlo_domain(smtp, checks)
        assert checks[0].status == Status.ERROR
        assert "does not include a domain name" in checks[0].details[0]


# ── _tag helper (mailvalidator/checks/smtp/_check.py) ─────────────────────────


class TestTagHelper:
    def test_tags_checks_from_start_index(self):
        """_tag assigns the section string to all checks from start onward."""
        from mailvalidator.checks.smtp._check import _tag
        from mailvalidator.models import CheckResult, Status

        checks = [
            CheckResult(name="A", status=Status.OK),
            CheckResult(name="B", status=Status.OK),
            CheckResult(name="C", status=Status.OK),
        ]
        _tag(checks, 1, "TLS")
        assert checks[0].section == ""   # untouched
        assert checks[1].section == "TLS"
        assert checks[2].section == "TLS"

    def test_tag_empty_slice_is_noop(self):
        """_tag with start == len(checks) touches nothing."""
        from mailvalidator.checks.smtp._check import _tag
        from mailvalidator.models import CheckResult, Status

        checks = [CheckResult(name="A", status=Status.OK)]
        _tag(checks, 1, "DNS")


# ── _connect_or_fallback ──────────────────────────────────────────────────────


class TestConnectOrFallback:
    def test_primary_port_succeeds(self):
        """Port 25 connects immediately — no fallback, actual_port == 25."""
        mock_smtp = MagicMock()
        with patch(
            "mailvalidator.checks.smtp._check._connect_plain",
            return_value=(mock_smtp, 42.0, "220 banner"),
        ) as mock_cp:
            smtp, ms, banner, actual, err = _connect_or_fallback(
                "mx.example.com", 25, (587, 465)
            )
        assert smtp is mock_smtp
        assert actual == 25
        assert err is None
        mock_cp.assert_called_once_with("mx.example.com", 25)

    def test_fallback_to_587_when_25_refused(self):
        """ConnectionRefusedError on 25 → success on 587."""
        mock_smtp = MagicMock()

        def _side(host, port):
            if port == 25:
                raise ConnectionRefusedError("refused")
            return mock_smtp, 55.0, "220 ok"

        with patch(
            "mailvalidator.checks.smtp._check._connect_plain", side_effect=_side
        ):
            smtp, _, _, actual, err = _connect_or_fallback(
                "mx.example.com", 25, (587, 465)
            )
        assert smtp is mock_smtp
        assert actual == 587
        assert err is None

    def test_fallback_to_465_when_25_and_587_refused(self):
        """Both 25 and 587 refused → success on 465."""
        mock_smtp = MagicMock()

        def _side(host, port):
            if port in (25, 587):
                raise ConnectionRefusedError("refused")
            return mock_smtp, 60.0, "220 ok"

        with patch(
            "mailvalidator.checks.smtp._check._connect_plain", side_effect=_side
        ):
            _, _, _, actual, err = _connect_or_fallback(
                "mx.example.com", 25, (587, 465)
            )
        assert actual == 465
        assert err is None

    def test_all_ports_fail_returns_error(self):
        """All three ports refused → smtp is None, error message lists every port."""
        with patch(
            "mailvalidator.checks.smtp._check._connect_plain",
            side_effect=ConnectionRefusedError("refused"),
        ):
            smtp, _, _, _, err = _connect_or_fallback(
                "mx.example.com", 25, (587, 465)
            )
        assert smtp is None
        assert err is not None
        assert "25" in err
        assert "587" in err
        assert "465" in err

    def test_non_refusal_oserror_no_fallback(self):
        """Generic OSError (e.g. network unreachable) → fail immediately, no retry."""
        with patch(
            "mailvalidator.checks.smtp._check._connect_plain",
            side_effect=OSError("network unreachable"),
        ) as mock_cp:
            smtp, _, _, _, err = _connect_or_fallback(
                "mx.example.com", 25, (587, 465)
            )
        assert smtp is None
        assert err is not None
        mock_cp.assert_called_once_with("mx.example.com", 25)

    def test_timeout_triggers_fallback(self):
        """TimeoutError on port 25 also triggers fallback (filtered port)."""
        mock_smtp = MagicMock()

        def _side(host, port):
            if port == 25:
                raise TimeoutError("timed out")
            return mock_smtp, 55.0, "220 ok"

        with patch(
            "mailvalidator.checks.smtp._check._connect_plain", side_effect=_side
        ):
            smtp, _, _, actual, err = _connect_or_fallback(
                "mx.example.com", 25, (587, 465)
            )
        assert actual == 587
        assert err is None

    def test_smtp_server_disconnected_triggers_fallback(self):
        """SMTPServerDisconnected (banner timeout) on port 25 should trigger fallback."""
        mock_smtp = MagicMock()

        def _side(host, port):
            if port == 25:
                raise smtplib.SMTPServerDisconnected(
                    "Connection unexpectedly closed: timed out"
                )
            return mock_smtp, 55.0, "220 ok"

        with patch(
            "mailvalidator.checks.smtp._check._connect_plain", side_effect=_side
        ):
            smtp, _, _, actual, err = _connect_or_fallback(
                "mx.example.com", 25, (587, 465)
            )
        assert smtp is mock_smtp
        assert actual == 587
        assert err is None

    def test_empty_fallback_no_retries(self):
        """Empty fallback tuple → only the primary port is attempted."""
        with patch(
            "mailvalidator.checks.smtp._check._connect_plain",
            side_effect=ConnectionRefusedError("refused"),
        ) as mock_cp:
            smtp, _, _, _, err = _connect_or_fallback("mx.example.com", 587, ())
        assert smtp is None
        assert err is not None
        mock_cp.assert_called_once_with("mx.example.com", 587)
