"""Unit tests for mailcheck – uses mocking so no live DNS needed."""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import pytest

from mailcheck.checks.bimi import check_bimi
from mailcheck.checks.dkim import check_dkim
from mailcheck.checks.dmarc import check_dmarc
from mailcheck.checks.mta_sts import check_mta_sts
from mailcheck.checks.mx import check_mx
from mailcheck.checks.spf import check_spf
from mailcheck.checks.tlsrpt import check_tlsrpt
from mailcheck.models import Status


# ── helpers ──────────────────────────────────────────────────────────────────


def _patch_resolve(return_value: list[str]):
    return patch("mailcheck.dns_utils.resolve", return_value=return_value)


def _patch_ns(return_value: list[str] | None = None):
    return patch(
        "mailcheck.dns_utils.get_authoritative_ns", return_value=return_value or []
    )


def _patch_resolve_a(return_value: list[str] | None = None):
    return patch(
        "mailcheck.dns_utils.resolve_a", return_value=return_value or ["1.2.3.4"]
    )


# ── MX ───────────────────────────────────────────────────────────────────────


class TestMX:
    def test_found(self):
        with _patch_ns(), _patch_resolve_a(), _patch_resolve(["10 mail.example.com."]):
            with patch(
                "mailcheck.checks.mx.resolve", return_value=["10 mail.example.com."]
            ):
                with patch("mailcheck.checks.mx.resolve_a", return_value=["1.2.3.4"]):
                    with patch(
                        "mailcheck.checks.mx.get_authoritative_ns", return_value=[]
                    ):
                        result = check_mx("example.com")
        assert len(result.records) == 1
        assert result.records[0].priority == 10
        assert result.records[0].exchange == "mail.example.com"
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("mailcheck.checks.mx.resolve", return_value=[]):
            with patch("mailcheck.checks.mx.get_authoritative_ns", return_value=[]):
                result = check_mx("nodomain.invalid")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_sorted_by_priority(self):
        records_raw = ["20 mail2.example.com.", "10 mail1.example.com."]
        with patch("mailcheck.checks.mx.resolve", return_value=records_raw):
            with patch("mailcheck.checks.mx.get_authoritative_ns", return_value=[]):
                with patch("mailcheck.checks.mx.resolve_a", return_value=["1.2.3.4"]):
                    result = check_mx("example.com")
        assert result.records[0].priority == 10
        assert result.records[1].priority == 20


# ── SPF ──────────────────────────────────────────────────────────────────────


class TestSPF:
    # ── Policy (all qualifier) ────────────────────────────────────────────────

    def test_fail_all_ok(self):
        """-all (fail) is a strict valid policy → OK."""
        with patch(
            "mailcheck.checks.spf.resolve", return_value=['"v=spf1 ip4:1.2.3.4 -all"']
        ):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK
        assert "-all" in policy.value

    def test_softfail_all_ok(self):
        """~all (softfail) is explicitly OK per the spec (preferred for most senders)."""
        with patch("mailcheck.checks.spf.resolve", return_value=['"v=spf1 ~all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK
        assert "~all" in policy.value

    def test_neutral_all_warning(self):
        """?all (neutral) provides no protection → WARNING."""
        with patch("mailcheck.checks.spf.resolve", return_value=['"v=spf1 ?all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING

    def test_plus_all_error(self):
        """+all (pass) authorises everyone → ERROR."""
        with patch("mailcheck.checks.spf.resolve", return_value=['"v=spf1 +all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.ERROR

    def test_missing_all_no_redirect_implies_neutral(self):
        """No 'all' and no redirect → RFC 7208 implicit ?all → WARNING."""
        with patch(
            "mailcheck.checks.spf.resolve", return_value=['"v=spf1 ip4:1.2.3.4"']
        ):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING
        assert "neutral" in " ".join(policy.details).lower()

    # ── Basic record checks ───────────────────────────────────────────────────

    def test_not_found(self):
        with patch("mailcheck.checks.spf.resolve", return_value=[]):
            result = check_spf("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_multiple_spf_records(self):
        with patch(
            "mailcheck.checks.spf.resolve",
            return_value=['"v=spf1 -all"', '"v=spf1 ~all"'],
        ):
            result = check_spf("example.com")
        assert any(
            c.status == Status.ERROR and "Multiple" in c.name for c in result.checks
        )

    def test_ptr_deprecation_warned(self):
        """ptr mechanism should trigger a deprecation warning."""
        with patch("mailcheck.checks.spf.resolve", return_value=['"v=spf1 ptr -all"']):
            result = check_spf("example.com")
        assert any(
            c.name == "ptr Mechanism" and c.status == Status.WARNING
            for c in result.checks
        )

    # ── include: recursive resolution ────────────────────────────────────────

    def test_include_is_resolved_and_shown(self):
        """include: records should be fetched recursively and shown in details."""

        def _fake_resolve(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:_spf.protonmail.ch ~all"']
            if domain == "_spf.protonmail.ch":
                return ['"v=spf1 ip4:185.70.40.0/24 ip4:185.70.41.0/24 -all"']
            return []

        with patch("mailcheck.checks.spf.resolve", side_effect=_fake_resolve):
            result = check_spf("example.com")

        resolution = next(
            (c for c in result.checks if c.name == "SPF Include Resolution"), None
        )
        assert resolution is not None, "Expected SPF Include Resolution check"
        assert resolution.status == Status.OK
        all_details = " ".join(resolution.details)
        assert "_spf.protonmail.ch" in all_details
        assert "185.70.40.0/24" in all_details

    def test_include_lookup_count_is_recursive(self):
        """Lookup count must span the full tree, not just the top-level record.

        Top-level:         include:_spf.protonmail.ch → 1 lookup
        _spf.protonmail.ch: a:mail.protonmail.ch       → 1 lookup
        Total: 2
        """

        def _fake_resolve(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:_spf.protonmail.ch -all"']
            if domain == "_spf.protonmail.ch":
                return ['"v=spf1 a:mail.protonmail.ch ip4:1.2.3.4 -all"']
            return []

        with patch("mailcheck.checks.spf.resolve", side_effect=_fake_resolve):
            result = check_spf("example.com")

        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/"), f"Expected 2/10, got {lookup.value}"

    def test_ptr_counts_as_lookup(self):
        """ptr is deprecated but still counts as one DNS lookup."""

        def _fake_resolve(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ptr -all"']
            return []

        with patch("mailcheck.checks.spf.resolve", side_effect=_fake_resolve):
            result = check_spf("example.com")

        # include(1) + ptr(1) = 2
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")

    def test_ip4_ip6_do_not_count_as_lookups(self):
        """ip4: and ip6: mechanisms must NOT count toward the lookup limit."""
        with patch(
            "mailcheck.checks.spf.resolve",
            return_value=['"v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all"'],
        ):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("0/")

    def test_include_missing_record_warns(self):
        """An include: pointing to a domain with no SPF record should warn."""

        def _fake_resolve(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:missing.example.com -all"']
            return []

        with patch("mailcheck.checks.spf.resolve", side_effect=_fake_resolve):
            result = check_spf("example.com")

        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert resolution.status == Status.WARNING

    def test_include_loop_is_handled(self):
        """Circular include: chains must not cause infinite recursion."""

        def _fake_resolve(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:a.example.com -all"']
            if domain == "a.example.com":
                return ['"v=spf1 include:b.example.com -all"']
            if domain == "b.example.com":
                return ['"v=spf1 include:a.example.com -all"']
            return []

        with patch("mailcheck.checks.spf.resolve", side_effect=_fake_resolve):
            result = check_spf("example.com")  # must not raise or hang

        assert result is not None

    def test_macro_in_include_not_followed(self):
        """include: targets containing macros must be noted but not fetched."""
        with patch(
            "mailcheck.checks.spf.resolve",
            return_value=['"v=spf1 include:%{d}._spf.example.com -all"'],
        ):
            result = check_spf("example.com")

        resolution = next(
            (c for c in result.checks if c.name == "SPF Include Resolution"), None
        )
        assert resolution is not None
        assert any("macro" in l.lower() for l in resolution.details)

    # ── redirect= modifier ────────────────────────────────────────────────────

    def test_redirect_is_followed(self):
        """redirect= delegates the entire policy; it should be followed."""

        def _fake_resolve(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 ip4:10.0.0.0/8 -all"']
            return []

        with patch("mailcheck.checks.spf.resolve", side_effect=_fake_resolve):
            result = check_spf("example.com")

        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK
        assert "redirect" in policy.value.lower()

    def test_redirect_lookup_counted(self):
        """redirect= costs one lookup plus the lookups inside the target."""

        def _fake_resolve(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 mx -all"']  # mx = 1 more lookup
            return []

        with patch("mailcheck.checks.spf.resolve", side_effect=_fake_resolve):
            result = check_spf("example.com")

        # redirect(1) + mx(1) = 2
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")


# ── DMARC ─────────────────────────────────────────────────────────────────────


class TestDMARC:
    def test_reject_policy(self):
        record = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
        with patch("mailcheck.checks.dmarc.resolve", return_value=[record]):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.OK for c in result.checks
        )

    def test_none_policy_warning(self):
        record = '"v=DMARC1; p=none"'
        with patch("mailcheck.checks.dmarc.resolve", return_value=[record]):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_missing_rua_warning(self):
        record = '"v=DMARC1; p=reject"'
        with patch("mailcheck.checks.dmarc.resolve", return_value=[record]):
            result = check_dmarc("example.com")
        assert any(
            "rua" in c.name.lower() and c.status == Status.WARNING
            for c in result.checks
        )


# ── DKIM ──────────────────────────────────────────────────────────────────────


class TestDKIM:
    def test_valid_record(self):
        record = '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA"'
        with patch("mailcheck.checks.dkim.resolve", return_value=[record]):
            result = check_dkim("example.com", selector="google")
        assert any(
            c.status == Status.OK and "Public Key" in c.name for c in result.checks
        )

    def test_not_found(self):
        with patch("mailcheck.checks.dkim.resolve", return_value=[]):
            result = check_dkim("example.com", selector="missing")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_revoked_key(self):
        record = '"v=DKIM1; k=rsa; p="'
        with patch("mailcheck.checks.dkim.resolve", return_value=[record]):
            result = check_dkim("example.com", selector="revoked")
        assert any(
            c.status in (Status.ERROR, Status.WARNING) and "Public Key" in c.name
            for c in result.checks
        )


# ── BIMI ──────────────────────────────────────────────────────────────────────


class TestBIMI:
    def test_valid_record(self):
        record = '"v=BIMI1; l=https://example.com/logo.svg"'
        with patch("mailcheck.checks.bimi.resolve", return_value=[record]):
            result = check_bimi("example.com")
        assert any(c.status == Status.OK and "Logo" in c.name for c in result.checks)

    def test_http_logo_error(self):
        record = '"v=BIMI1; l=http://example.com/logo.svg"'
        with patch("mailcheck.checks.bimi.resolve", return_value=[record]):
            result = check_bimi("example.com")
        assert any(c.status == Status.ERROR and "Logo" in c.name for c in result.checks)


# ── TLSRPT ───────────────────────────────────────────────────────────────────


class TestTLSRPT:
    def test_valid(self):
        record = '"v=TLSRPTv1; rua=mailto:tls@example.com"'
        with patch("mailcheck.checks.tlsrpt.resolve", return_value=[record]):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("mailcheck.checks.tlsrpt.resolve", return_value=[]):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)


# ── MTA-STS ──────────────────────────────────────────────────────────────────


class TestMTASTS:
    def test_valid(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
        )
        with patch("mailcheck.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailcheck.checks.mta_sts._fetch_policy", return_value=(policy_text, "")
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.OK for c in result.checks
        )

    def test_not_found(self):
        with patch("mailcheck.checks.mta_sts.resolve", return_value=[]):
            result = check_mta_sts("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)


# ── SMTP TLS checks ───────────────────────────────────────────────────────────

from mailcheck.checks.smtp import (
    _check_cipher,
    _check_cipher_order,
    _enumerate_ciphers_for_version,
    _detect_server_cipher_order,
    _tlsa_fingerprint,
    _verify_tlsa_record,
    _check_dane,
    _check_compression,
    _check_hash_function,
    _check_key_exchange,
    _check_tls_version,
    _probe_single_tls_version,
    _classify_cipher,
    _classify_ec_curve,
    _tls_version_status,
)
from mailcheck.models import Status, TLSDetails


def _make_tls(**kwargs) -> TLSDetails:
    defaults = dict(
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        dh_group="x25519",
        dh_bits=256,
        compression="",
        secure_renegotiation=True,
        cert_subject="CN=mail.example.com",
    )
    defaults.update(kwargs)
    return TLSDetails(**defaults)


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
            "mailcheck.checks.smtp._probe_single_tls_version",
            side_effect=lambda h, p, helo, sni, tls_min, tls_max: (
                tls_min == ssl.TLSVersion.TLSv1_3
            ),
        ):
            _check_tls_version(
                "mail.example.com",
                25,
                "mailcheck.local",
                "mail.example.com",
                _make_tls(tls_version="TLSv1.3"),
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
            "mailcheck.checks.smtp._probe_single_tls_version",
            side_effect=_accept_tls11_only,
        ):
            _check_tls_version(
                "mail.example.com",
                25,
                "mailcheck.local",
                "mail.example.com",
                _make_tls(tls_version="TLSv1.1"),
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
        tls = _make_tls()
        # Simulate enumeration returning ciphers for TLS 1.3 only
        with patch(
            "mailcheck.checks.smtp._enumerate_ciphers_for_version",
            side_effect=lambda h, p, helo, sni, mn, mx, **kw: (
                ["TLS_AES_256_GCM_SHA384"] if mn == ssl.TLSVersion.TLSv1_3 else []
            ),
        ):
            _check_cipher(
                "mail.example.com",
                25,
                "mailcheck.local",
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
        tls = _make_tls()
        tls.offered_ciphers_by_version = ciphers_by_version
        return tls

    def test_good_only_is_na(self):
        checks: list = []
        tls = self._tls(
            {"TLSv1.3": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]}
        )
        with patch(
            "mailcheck.checks.smtp._detect_server_cipher_order", return_value=True
        ):
            _check_cipher_order(
                "mail.example.com",
                25,
                "mailcheck.local",
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
            "mailcheck.checks.smtp._detect_server_cipher_order", return_value=True
        ):
            _check_cipher_order(
                "mail.example.com",
                25,
                "mailcheck.local",
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
            "mailcheck.checks.smtp._detect_server_cipher_order", return_value=True
        ):
            _check_cipher_order(
                "mail.example.com",
                25,
                "mailcheck.local",
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
        tls = _make_tls(cipher_name="ECDHE-RSA-AES256-GCM-SHA384", dh_group="secp256r1")
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.GOOD

    def test_dhe_sufficient(self):
        checks: list = []
        tls = _make_tls(
            cipher_name="DHE-RSA-AES256-GCM-SHA384", dh_bits=3072, tls_version="TLSv1.2"
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.SUFFICIENT

    def test_dhe_phase_out(self):
        checks: list = []
        tls = _make_tls(
            cipher_name="DHE-RSA-AES256-GCM-SHA384", dh_bits=2048, tls_version="TLSv1.2"
        )
        _check_key_exchange(tls, checks)
        assert checks[0].status == Status.PHASE_OUT


class TestHashFunction:
    def test_tls13_always_good(self):
        checks: list = []
        _check_hash_function(_make_tls(tls_version="TLSv1.3"), checks)
        assert checks[0].status == Status.GOOD

    def test_sha384_good(self):
        checks: list = []
        _check_hash_function(
            _make_tls(tls_version="TLSv1.2", cipher_name="ECDHE-RSA-AES256-GCM-SHA384"),
            checks,
        )
        assert checks[0].status == Status.GOOD

    def test_sha1_phase_out(self):
        checks: list = []
        _check_hash_function(
            _make_tls(tls_version="TLSv1.2", cipher_name="ECDHE-RSA-AES128-SHA"), checks
        )
        assert checks[0].status == Status.PHASE_OUT


class TestCompression:
    def test_no_compression_good(self):
        checks: list = []
        _check_compression(_make_tls(compression=""), checks)
        assert checks[0].status == Status.GOOD

    def test_deflate_insufficient(self):
        checks: list = []
        _check_compression(_make_tls(compression="deflate"), checks)
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
        with patch("mailcheck.checks.smtp.resolve", return_value=[]):
            _check_dane(
                "mail.example.com",
                25,
                "mailcheck.local",
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
        with patch("mailcheck.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com",
                25,
                "mailcheck.local",
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
        with patch("mailcheck.checks.smtp.resolve", return_value=[record]):
            _check_dane(
                "mail.example.com",
                25,
                "mailcheck.local",
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
            "mailcheck.checks.smtp.resolve", return_value=[current_record, next_record]
        ):
            _check_dane(
                "mail.example.com",
                25,
                "mailcheck.local",
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
            "mailcheck.checks.smtp.resolve",
            return_value=["0 0 1 " + "aa" * 32, "1 0 1 " + "bb" * 32],
        ):
            _check_dane(
                "mail.example.com",
                25,
                "mailcheck.local",
                "mail.example.com",
                None,
                checks,
            )
        exist_check = next(c for c in checks if "Existence" in c.name)
        assert exist_check.status == Status.WARNING
