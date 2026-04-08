"""Tests for mailvalidator/checks/dmarc.py — RFC 7489 compliance."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.dmarc import (
    _check_alignment,
    _check_fo,
    _check_pct,
    _check_policy,
    _check_reporting_uris,
    _check_ri,
    _check_subdomain_policy,
    _check_version_first,
    _first_tag,
    _org_domain,
    _parse_tags,
    check_dmarc,
)
from mailvalidator.models import DMARCResult, Status

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result() -> DMARCResult:
    return DMARCResult(domain="example.com")


def _resolve_none(*args, **kwargs):
    """Stub: resolve returns no records (used for external-verify tests)."""
    return []


def _resolve_dmarc1(*args, **kwargs):
    """Stub: resolve returns a confirming v=DMARC1 record."""
    return ['"v=DMARC1"']


# ---------------------------------------------------------------------------
# _parse_tags
# ---------------------------------------------------------------------------


class TestParseTags:
    def test_basic_record(self):
        tags = _parse_tags("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
        assert tags == {"v": "DMARC1", "p": "reject", "rua": "mailto:dmarc@example.com"}

    def test_strips_whitespace(self):
        tags = _parse_tags("v=DMARC1;  p = reject ")
        assert tags["p"] == "reject"

    def test_ignores_entries_without_equals(self):
        tags = _parse_tags("v=DMARC1; garbage; p=none")
        assert "garbage" not in tags
        assert tags["p"] == "none"

    def test_empty_string(self):
        assert _parse_tags("") == {}


# ---------------------------------------------------------------------------
# _first_tag
# ---------------------------------------------------------------------------


class TestFirstTag:
    def test_v_first(self):
        assert _first_tag("v=DMARC1; p=reject") == "v"

    def test_p_first(self):
        assert _first_tag("p=reject; v=DMARC1") == "p"

    def test_empty(self):
        assert _first_tag("") == ""


# ---------------------------------------------------------------------------
# _org_domain
# ---------------------------------------------------------------------------


class TestOrgDomain:
    def test_subdomain(self):
        assert _org_domain("mail.example.com") == "example.com"

    def test_apex(self):
        assert _org_domain("example.com") == "example.com"

    def test_single_label(self):
        assert _org_domain("localhost") == "localhost"

    def test_trailing_dot_stripped(self):
        assert _org_domain("example.com.") == "example.com"

    def test_deep_subdomain(self):
        assert _org_domain("a.b.c.example.com") == "example.com"


# ---------------------------------------------------------------------------
# _check_version_first  (RFC 7489 §6.3)
# ---------------------------------------------------------------------------


class TestCheckVersionFirst:
    def test_v_first_no_error(self):
        r = _result()
        _check_version_first("v=DMARC1; p=reject", r)
        assert not r.checks

    def test_p_first_produces_error(self):
        r = _result()
        _check_version_first("p=reject; v=DMARC1", r)
        assert len(r.checks) == 1
        assert r.checks[0].status == Status.ERROR
        assert "first tag" in r.checks[0].details[0].lower()


# ---------------------------------------------------------------------------
# _check_policy  (RFC 7489 §6.3)
# ---------------------------------------------------------------------------


class TestCheckPolicy:
    def test_reject_ok(self):
        r = _result()
        _check_policy({"p": "reject"}, r)
        assert r.checks[0].status == Status.OK
        assert r.checks[0].value == "reject"

    def test_quarantine_ok(self):
        r = _result()
        _check_policy({"p": "quarantine"}, r)
        assert r.checks[0].status == Status.OK

    def test_none_warning(self):
        r = _result()
        _check_policy({"p": "none"}, r)
        assert r.checks[0].status == Status.WARNING

    def test_missing_error(self):
        r = _result()
        _check_policy({}, r)
        assert r.checks[0].status == Status.ERROR

    def test_invalid_value_error(self):
        r = _result()
        _check_policy({"p": "invalid"}, r)
        assert r.checks[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_subdomain_policy  (RFC 7489 §6.3)
# ---------------------------------------------------------------------------


class TestCheckSubdomainPolicy:
    def test_absent_no_check(self):
        r = _result()
        _check_subdomain_policy({}, r)
        assert not r.checks

    def test_valid_value_info(self):
        r = _result()
        _check_subdomain_policy({"sp": "reject"}, r)
        assert r.checks[0].status == Status.INFO

    def test_invalid_value_error(self):
        r = _result()
        _check_subdomain_policy({"sp": "invalid"}, r)
        assert r.checks[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_pct  (RFC 7489 §6.4)
# ---------------------------------------------------------------------------


class TestCheckPct:
    def test_default_100_ok(self):
        r = _result()
        _check_pct({}, r)
        assert r.checks[0].status == Status.OK
        assert r.checks[0].value == "100%"

    def test_explicit_100_ok(self):
        r = _result()
        _check_pct({"pct": "100"}, r)
        assert r.checks[0].status == Status.OK

    def test_partial_warning(self):
        r = _result()
        _check_pct({"pct": "50"}, r)
        assert r.checks[0].status == Status.WARNING
        assert "50%" in r.checks[0].value

    def test_zero_warning(self):
        r = _result()
        _check_pct({"pct": "0"}, r)
        assert r.checks[0].status == Status.WARNING

    def test_above_100_error(self):
        r = _result()
        _check_pct({"pct": "101"}, r)
        assert r.checks[0].status == Status.ERROR

    def test_negative_error(self):
        r = _result()
        _check_pct({"pct": "-1"}, r)
        assert r.checks[0].status == Status.ERROR

    def test_non_integer_error(self):
        r = _result()
        _check_pct({"pct": "abc"}, r)
        assert r.checks[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_alignment  (RFC 7489 §6.4)
# ---------------------------------------------------------------------------


class TestCheckAlignment:
    def test_relaxed_default(self):
        r = _result()
        _check_alignment({}, r)
        assert all(c.status == Status.INFO for c in r.checks)
        assert all(c.value == "relaxed" for c in r.checks)

    def test_strict_value(self):
        r = _result()
        _check_alignment({"adkim": "s", "aspf": "s"}, r)
        assert all(c.value == "strict" for c in r.checks)

    def test_invalid_adkim_error(self):
        r = _result()
        _check_alignment({"adkim": "x"}, r)
        assert any(c.status == Status.ERROR for c in r.checks)

    def test_invalid_aspf_error(self):
        r = _result()
        _check_alignment({"aspf": "z"}, r)
        assert any(c.status == Status.ERROR for c in r.checks)


# ---------------------------------------------------------------------------
# _check_fo  (RFC 7489 §6.4)
# ---------------------------------------------------------------------------


class TestCheckFo:
    def test_absent_no_check(self):
        r = _result()
        _check_fo({}, r)
        assert not r.checks

    def test_valid_single(self):
        r = _result()
        _check_fo({"fo": "1"}, r)
        assert r.checks[0].status == Status.INFO

    def test_valid_combined(self):
        r = _result()
        _check_fo({"fo": "1:d:s"}, r)
        assert r.checks[0].status == Status.INFO

    def test_all_valid_options(self):
        for opt in ("0", "1", "d", "s"):
            r = _result()
            _check_fo({"fo": opt}, r)
            assert r.checks[0].status == Status.INFO

    def test_invalid_option_error(self):
        r = _result()
        _check_fo({"fo": "x"}, r)
        assert r.checks[0].status == Status.ERROR

    def test_mixed_valid_invalid_error(self):
        r = _result()
        _check_fo({"fo": "1:z"}, r)
        assert r.checks[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_ri  (RFC 7489 §6.4)
# ---------------------------------------------------------------------------


class TestCheckRi:
    def test_absent_no_check(self):
        r = _result()
        _check_ri({}, r)
        assert not r.checks

    def test_valid_integer_info(self):
        r = _result()
        _check_ri({"ri": "86400"}, r)
        assert r.checks[0].status == Status.INFO
        assert "86400s" in r.checks[0].value

    def test_zero_error(self):
        r = _result()
        _check_ri({"ri": "0"}, r)
        assert r.checks[0].status == Status.ERROR

    def test_negative_error(self):
        r = _result()
        _check_ri({"ri": "-100"}, r)
        assert r.checks[0].status == Status.ERROR

    def test_non_integer_error(self):
        r = _result()
        _check_ri({"ri": "daily"}, r)
        assert r.checks[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_reporting_uris — scheme, mailto syntax, external verify (RFC 7489 §6.4, §7.1)
# ---------------------------------------------------------------------------


class TestCheckReportingUris:
    def _call(self, tag, raw_value, resolve_side_effect=None):
        r = _result()
        tags = {tag: raw_value} if raw_value else {}
        resolve_fn = resolve_side_effect or _resolve_none
        with patch("mailvalidator.checks.dmarc.resolve", side_effect=resolve_fn):
            _check_reporting_uris(tag, f"{tag.upper()} Reports", "example.com", tags, r)
        return r

    # ── absent tag ───────────────────────────────────────────────────────────

    def test_rua_absent_warning(self):
        r = self._call("rua", "")
        assert r.checks[0].status == Status.WARNING

    def test_ruf_absent_no_check(self):
        r = self._call("ruf", "")
        assert not r.checks

    # ── scheme validation ─────────────────────────────────────────────────

    def test_valid_mailto_ok(self):
        r = self._call("rua", "mailto:dmarc@example.com")
        assert r.checks[0].status == Status.OK

    def test_valid_https_ok(self):
        r = self._call("rua", "https://reports.example.com/dmarc")
        assert r.checks[0].status == Status.OK

    def test_invalid_scheme_error(self):
        r = self._call("rua", "ftp://reports.example.com")
        assert r.checks[0].status == Status.ERROR
        assert any("unsupported scheme" in d for d in r.checks[0].details)

    def test_http_scheme_error(self):
        r = self._call("rua", "http://reports.example.com/dmarc")
        assert r.checks[0].status == Status.ERROR

    # ── mailto: address syntax ────────────────────────────────────────────

    def test_invalid_mailto_address_error(self):
        r = self._call("rua", "mailto:notanemail")
        assert r.checks[0].status == Status.ERROR

    def test_mailto_missing_at_error(self):
        r = self._call("rua", "mailto:noatsign")
        assert r.checks[0].status == Status.ERROR

    # ── multiple URIs ─────────────────────────────────────────────────────

    def test_multiple_valid_uris_ok(self):
        r = self._call("rua", "mailto:a@example.com,mailto:b@example.com")
        assert r.checks[0].status == Status.OK

    def test_one_invalid_among_multiple_error(self):
        r = self._call("rua", "mailto:good@example.com,ftp://bad.example.com")
        assert r.checks[0].status == Status.ERROR

    # ── same-domain: no external verification needed ──────────────────────

    def test_same_domain_no_dns_lookup(self):
        r = _result()
        tags = {"rua": "mailto:dmarc@example.com"}
        with patch("mailvalidator.checks.dmarc.resolve") as mock_resolve:
            _check_reporting_uris("rua", "rua", "example.com", tags, r)
        mock_resolve.assert_not_called()
        assert r.checks[0].status == Status.OK

    def test_same_org_domain_subdomain_no_lookup(self):
        """mail.example.com shares org domain with example.com — no DNS lookup."""
        r = _result()
        tags = {"rua": "mailto:dmarc@mail.example.com"}
        with patch("mailvalidator.checks.dmarc.resolve") as mock_resolve:
            _check_reporting_uris("rua", "rua", "example.com", tags, r)
        mock_resolve.assert_not_called()
        assert r.checks[0].status == Status.OK

    # ── external destination verification (RFC 7489 §7.1) ─────────────────

    def test_external_destination_verified_ok(self):
        """Cross-domain rua= with confirming TXT → OK."""
        r = _result()
        tags = {"rua": "mailto:reports@other.example.net"}
        with patch("mailvalidator.checks.dmarc.resolve", return_value=['"v=DMARC1"']):
            _check_reporting_uris("rua", "rua", "example.com", tags, r)
        assert r.checks[0].status == Status.OK
        assert any("verified" in d for d in r.checks[0].details)

    def test_external_destination_not_verified_warning(self):
        """Cross-domain rua= with no confirming TXT → WARNING."""
        r = _result()
        tags = {"rua": "mailto:reports@other.example.net"}
        with patch("mailvalidator.checks.dmarc.resolve", return_value=[]):
            _check_reporting_uris("rua", "rua", "example.com", tags, r)
        assert r.checks[0].status == Status.WARNING
        assert any("NOT verified" in d for d in r.checks[0].details)

    def test_external_verification_uses_correct_dns_name(self):
        """Verification query must be <domain>._report._dmarc.<report-host> (§7.1)."""
        r = _result()
        tags = {"rua": "mailto:reports@other.net"}
        calls_made = []

        def capture_resolve(name, rdtype, **kwargs):
            calls_made.append(name)
            return []

        with patch("mailvalidator.checks.dmarc.resolve", side_effect=capture_resolve):
            _check_reporting_uris("rua", "rua", "example.com", tags, r)
        assert any("example.com._report._dmarc.other.net" in c for c in calls_made)

    def test_external_https_uri_verified(self):
        """https: URIs also trigger external verification when cross-domain."""
        r = _result()
        tags = {"rua": "https://reports.other.net/dmarc"}
        with patch("mailvalidator.checks.dmarc.resolve", return_value=['"v=DMARC1"']):
            _check_reporting_uris("rua", "rua", "example.com", tags, r)
        assert r.checks[0].status == Status.OK

    def test_ruf_external_not_verified_warning(self):
        """External ruf= also requires §7.1 verification."""
        r = _result()
        tags = {"ruf": "mailto:forensic@other.net"}
        with patch("mailvalidator.checks.dmarc.resolve", return_value=[]):
            _check_reporting_uris("ruf", "ruf", "example.com", tags, r)
        assert r.checks[0].status == Status.WARNING


# ---------------------------------------------------------------------------
# check_dmarc — integration-level tests
# ---------------------------------------------------------------------------


class TestCheckDmarc:
    def _resolve(self, dmarc_record):
        """Return a resolve stub that always returns the given DMARC record."""
        return patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=[dmarc_record],
        )

    # ── record lookup ────────────────────────────────────────────────────────

    def test_not_found(self):
        with patch("mailvalidator.checks.dmarc.resolve", return_value=[]):
            result = check_dmarc("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_multiple_records_error(self):
        with patch(
            "mailvalidator.checks.dmarc.resolve",
            return_value=['"v=DMARC1; p=reject"', '"v=DMARC1; p=none"'],
        ):
            result = check_dmarc("example.com")
        assert any(
            "Multiple" in c.name and c.status == Status.ERROR for c in result.checks
        )

    def test_record_stored(self):
        with self._resolve('"v=DMARC1; p=reject; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert "v=DMARC1" in result.record

    # ── well-formed full records ─────────────────────────────────────────────

    def test_reject_with_rua_fully_ok(self):
        with self._resolve('"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'):
            result = check_dmarc("example.com")
        statuses = {c.name: c.status for c in result.checks}
        assert statuses["Policy (p=)"] == Status.OK
        assert statuses["Aggregate Reports (rua=)"] == Status.OK
        assert statuses["Percentage (pct=)"] == Status.OK

    def test_none_policy_produces_warning(self):
        with self._resolve('"v=DMARC1; p=none"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Policy (p=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_missing_rua_produces_warning(self):
        with self._resolve('"v=DMARC1; p=reject"'):
            result = check_dmarc("example.com")
        assert any(
            "rua" in c.name.lower() and c.status == Status.WARNING
            for c in result.checks
        )

    # ── version ordering ─────────────────────────────────────────────────────

    def test_v_not_first_produces_error(self):
        with self._resolve('"p=reject; v=DMARC1"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Tag Order (v=)" and c.status == Status.ERROR
            for c in result.checks
        )

    # ── subdomain policy ─────────────────────────────────────────────────────

    def test_valid_sp_reported(self):
        with self._resolve('"v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert any(c.name == "Subdomain Policy (sp=)" for c in result.checks)

    def test_invalid_sp_error(self):
        with self._resolve('"v=DMARC1; p=reject; sp=bogus; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Subdomain Policy (sp=)" and c.status == Status.ERROR
            for c in result.checks
        )

    # ── pct ──────────────────────────────────────────────────────────────────

    def test_pct_50_warning(self):
        with self._resolve('"v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Percentage (pct=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_pct_invalid_error(self):
        with self._resolve('"v=DMARC1; p=reject; pct=abc"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Percentage (pct=)" and c.status == Status.ERROR
            for c in result.checks
        )

    def test_pct_out_of_range_error(self):
        with self._resolve('"v=DMARC1; p=reject; pct=200"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Percentage (pct=)" and c.status == Status.ERROR
            for c in result.checks
        )

    # ── alignment ────────────────────────────────────────────────────────────

    def test_strict_adkim(self):
        with self._resolve('"v=DMARC1; p=reject; adkim=s; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "DKIM Alignment (adkim=)" and c.value == "strict"
            for c in result.checks
        )

    def test_invalid_alignment_error(self):
        with self._resolve('"v=DMARC1; p=reject; adkim=x"'):
            result = check_dmarc("example.com")
        assert any(
            "DKIM Alignment" in c.name and c.status == Status.ERROR
            for c in result.checks
        )

    # ── fo ───────────────────────────────────────────────────────────────────

    def test_valid_fo_info(self):
        with self._resolve('"v=DMARC1; p=reject; fo=1; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Forensic Options (fo=)" and c.status == Status.INFO
            for c in result.checks
        )

    def test_invalid_fo_error(self):
        with self._resolve('"v=DMARC1; p=reject; fo=x; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Forensic Options (fo=)" and c.status == Status.ERROR
            for c in result.checks
        )

    # ── ri ───────────────────────────────────────────────────────────────────

    def test_valid_ri_info(self):
        with self._resolve('"v=DMARC1; p=reject; ri=3600; rua=mailto:d@example.com"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Reporting Interval (ri=)" and c.status == Status.INFO
            for c in result.checks
        )

    def test_invalid_ri_error(self):
        with self._resolve('"v=DMARC1; p=reject; ri=0"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "Reporting Interval (ri=)" and c.status == Status.ERROR
            for c in result.checks
        )

    # ── ruf ──────────────────────────────────────────────────────────────────

    def test_ruf_reported(self):
        with self._resolve(
            '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com"'
        ):
            result = check_dmarc("example.com")
        assert any("Forensic Reports" in c.name for c in result.checks)

    # ── external verification end-to-end ─────────────────────────────────────

    def test_cross_domain_rua_verified(self):
        def resolve_stub(name, rdtype, **kwargs):
            if "_report._dmarc" in name:
                return ['"v=DMARC1"']
            return ['"v=DMARC1; p=reject; rua=mailto:reports@thirdparty.net"']

        with patch("mailvalidator.checks.dmarc.resolve", side_effect=resolve_stub):
            result = check_dmarc("example.com")
        assert any(
            "Aggregate Reports" in c.name and c.status == Status.OK
            for c in result.checks
        )

    def test_cross_domain_rua_not_verified(self):
        def resolve_stub(name, rdtype, **kwargs):
            if "_report._dmarc" in name:
                return []
            return ['"v=DMARC1; p=reject; rua=mailto:reports@thirdparty.net"']

        with patch("mailvalidator.checks.dmarc.resolve", side_effect=resolve_stub):
            result = check_dmarc("example.com")
        assert any(
            "Aggregate Reports" in c.name and c.status == Status.WARNING
            for c in result.checks
        )

    # ── duplicate tags ────────────────────────────────────────────────────────

    def test_duplicate_tag_warning(self):
        """RFC 7489 §6.3: duplicate tags in a DMARC record must produce a WARNING."""
        with self._resolve('"v=DMARC1; p=reject; p=none; rua=mailto:dmarc@example.com"'):
            result = check_dmarc("example.com")
        assert any(
            c.name == "DMARC Record" and c.status == Status.WARNING
            and "Duplicate tag" in (c.details[0] if c.details else "")
            for c in result.checks
        )

    def test_no_duplicate_tag_no_warning(self):
        """No duplicate-tag warning when all tags are unique."""
        with self._resolve('"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'):
            result = check_dmarc("example.com")
        assert not any(
            c.name == "DMARC Record" and c.status == Status.WARNING
            and "Duplicate tag" in (c.details[0] if c.details else "")
            for c in result.checks
        )

    def test_multiple_duplicate_tags_listed(self):
        """Multiple duplicate tags are all listed in the warning detail."""
        with self._resolve('"v=DMARC1; p=reject; p=none; rua=mailto:a@example.com; rua=mailto:b@example.com"'):
            result = check_dmarc("example.com")
        dup_warnings = [
            c for c in result.checks
            if c.name == "DMARC Record" and c.status == Status.WARNING
            and "Duplicate tag" in (c.details[0] if c.details else "")
        ]
        assert dup_warnings
        assert "p" in dup_warnings[0].details[0]
        assert "rua" in dup_warnings[0].details[0]
