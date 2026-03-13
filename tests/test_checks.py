"""Unit tests for mailcheck – uses mocking so no live DNS needed."""

from __future__ import annotations

from unittest.mock import patch

from checks.bimi import check_bimi
from checks.dkim import check_dkim
from checks.dmarc import check_dmarc
from checks.mta_sts import check_mta_sts
from checks.mx import check_mx
from checks.spf import check_spf
from checks.tlsrpt import check_tlsrpt
from models import Status

# ── helpers ──────────────────────────────────────────────────────────────────


def _patch_resolve(return_value: list[str]):
    return patch("dns_utils.resolve", return_value=return_value)


def _patch_ns(return_value: list[str] | None = None):
    return patch("dns_utils.get_authoritative_ns", return_value=return_value or [])


def _patch_resolve_a(return_value: list[str] | None = None):
    return patch("dns_utils.resolve_a", return_value=return_value or ["1.2.3.4"])


# ── MX ───────────────────────────────────────────────────────────────────────


class TestMX:
    def test_found(self):
        with _patch_ns(), _patch_resolve_a(), _patch_resolve(["10 mail.example.com."]):
            with patch("checks.mx.resolve", return_value=["10 mail.example.com."]):
                with patch("checks.mx.resolve_a", return_value=["1.2.3.4"]):
                    with patch("checks.mx.get_authoritative_ns", return_value=[]):
                        result = check_mx("example.com")
        assert len(result.records) == 1
        assert result.records[0].priority == 10
        assert result.records[0].exchange == "mail.example.com"
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("checks.mx.resolve", return_value=[]):
            with patch("checks.mx.get_authoritative_ns", return_value=[]):
                result = check_mx("nodomain.invalid")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_sorted_by_priority(self):
        records_raw = ["20 mail2.example.com.", "10 mail1.example.com."]
        with patch("checks.mx.resolve", return_value=records_raw):
            with patch("checks.mx.get_authoritative_ns", return_value=[]):
                with patch("checks.mx.resolve_a", return_value=["1.2.3.4"]):
                    result = check_mx("example.com")
        assert result.records[0].priority == 10
        assert result.records[1].priority == 20


# ── SPF ──────────────────────────────────────────────────────────────────────


class TestSPF:
    def test_valid_reject_all(self):
        with patch(
            "checks.spf.resolve", return_value=['"v=spf1 include:_spf.google.com -all"']
        ):
            result = check_spf("example.com")
        assert any(
            c.status == Status.OK and "all" in c.name.lower() for c in result.checks
        )

    def test_softfail_warning(self):
        with patch("checks.spf.resolve", return_value=['"v=spf1 ~all"']):
            result = check_spf("example.com")
        assert any(
            c.status == Status.WARNING and "all" in c.name.lower()
            for c in result.checks
        )

    def test_plus_all_error(self):
        with patch("checks.spf.resolve", return_value=['"v=spf1 +all"']):
            result = check_spf("example.com")
        assert any(c.status == Status.ERROR for c in result.checks)

    def test_not_found(self):
        with patch("checks.spf.resolve", return_value=[]):
            result = check_spf("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_multiple_spf_records(self):
        with patch(
            "checks.spf.resolve", return_value=['"v=spf1 -all"', '"v=spf1 ~all"']
        ):
            result = check_spf("example.com")
        assert any(
            c.status == Status.ERROR and "Multiple" in c.name for c in result.checks
        )


# ── DMARC ─────────────────────────────────────────────────────────────────────


class TestDMARC:
    def test_reject_policy(self):
        record = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
        with patch("checks.dmarc.resolve", return_value=[record]):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.OK for c in result.checks
        )

    def test_none_policy_warning(self):
        record = '"v=DMARC1; p=none"'
        with patch("checks.dmarc.resolve", return_value=[record]):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_missing_rua_warning(self):
        record = '"v=DMARC1; p=reject"'
        with patch("checks.dmarc.resolve", return_value=[record]):
            result = check_dmarc("example.com")
        assert any(
            "rua" in c.name.lower() and c.status == Status.WARNING
            for c in result.checks
        )


# ── DKIM ──────────────────────────────────────────────────────────────────────


class TestDKIM:
    def test_valid_record(self):
        record = '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA"'
        with patch("checks.dkim.resolve", return_value=[record]):
            result = check_dkim("example.com", selector="google")
        assert any(
            c.status == Status.OK and "Public Key" in c.name for c in result.checks
        )

    def test_not_found(self):
        with patch("checks.dkim.resolve", return_value=[]):
            result = check_dkim("example.com", selector="missing")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_revoked_key(self):
        record = '"v=DKIM1; k=rsa; p="'
        with patch("checks.dkim.resolve", return_value=[record]):
            result = check_dkim("example.com", selector="revoked")
        assert any(
            c.status in (Status.ERROR, Status.WARNING) and "Public Key" in c.name
            for c in result.checks
        )


# ── BIMI ──────────────────────────────────────────────────────────────────────


class TestBIMI:
    def test_valid_record(self):
        record = '"v=BIMI1; l=https://example.com/logo.svg"'
        with patch("checks.bimi.resolve", return_value=[record]):
            result = check_bimi("example.com")
        assert any(c.status == Status.OK and "Logo" in c.name for c in result.checks)

    def test_http_logo_error(self):
        record = '"v=BIMI1; l=http://example.com/logo.svg"'
        with patch("checks.bimi.resolve", return_value=[record]):
            result = check_bimi("example.com")
        assert any(c.status == Status.ERROR and "Logo" in c.name for c in result.checks)


# ── TLSRPT ───────────────────────────────────────────────────────────────────


class TestTLSRPT:
    def test_valid(self):
        record = '"v=TLSRPTv1; rua=mailto:tls@example.com"'
        with patch("checks.tlsrpt.resolve", return_value=[record]):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("checks.tlsrpt.resolve", return_value=[]):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)


# ── MTA-STS ──────────────────────────────────────────────────────────────────


class TestMTASTS:
    def test_valid(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy_text = (
            "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
        )
        with patch("checks.mta_sts.resolve", return_value=[dns_record]):
            with patch("checks.mta_sts._fetch_policy", return_value=(policy_text, "")):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.OK for c in result.checks
        )

    def test_not_found(self):
        with patch("checks.mta_sts.resolve", return_value=[]):
            result = check_mta_sts("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)
