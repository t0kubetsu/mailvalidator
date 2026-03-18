"""Tests for mailvalidator/checks/smtp.py – pure-logic checks only.

Network I/O functions (_probe_tls, check_smtp, etc.) require a live SMTP
server and are covered by integration tests only.
"""

from __future__ import annotations

import datetime as _dt
import ssl
from unittest.mock import MagicMock, patch

import smtplib

import pytest

from mailvalidator.checks.smtp import (
    _cert_info,
    _check_caa,
    _check_certificate,
    _check_cipher,
    _check_cipher_order,
    _check_compression,
    _check_dane,
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
    _tlsa_fingerprint,
    _tls_version_status,
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
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

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
            "mailvalidator.checks.smtp.resolve", return_value=[current_record, next_record]
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
            _check_cipher("mail.example.com", 25, "mailvalidator.local", None, tls, checks)
        cipher_check = next(c for c in checks if "TLSv1.2" in c.name)
        assert cipher_check.status == Status.PHASE_OUT


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
            "mailvalidator.checks.smtp.resolve", return_value=['0 issue "letsencrypt.org"']
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
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record1, record2]):
            _check_dane("mail.example.com", 25, "mailvalidator.local", None, der, checks)
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
        with patch("mailvalidator.checks.smtp.resolve", return_value=[record1, record2]):
            _check_dane("mail.example.com", 25, "mailvalidator.local", None, der, checks)
        rollover = next(c for c in checks if "Rollover" in c.name)
        assert rollover.status == Status.OK
        assert "EE + DANE-EE" in rollover.details[0]


# ── Final gap: DANE-EE + DANE-TA rollover combination (smtp.py L1863) ────────


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
            _check_dane("mail.example.com", 25, "mailvalidator.local", None, der, checks)
        rollover = next(c for c in checks if "Rollover" in c.name)
        assert rollover.status == Status.OK
        assert "EE + DANE-TA" in rollover.details[0]
