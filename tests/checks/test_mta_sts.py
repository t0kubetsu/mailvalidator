"""Tests for mailvalidator/checks/mta_sts.py."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

from mailvalidator.checks.mta_sts import (
    _fetch_policy,
    _parse_policy_file,
    _validate_policy,
    check_mta_sts,
)
from mailvalidator.models import MTASTSResult, Status

# _fetch_policy now returns (text, content_type, error) — 3-tuple throughout.
_OK_POLICY = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
_OK_FETCH = (_OK_POLICY, "text/plain", "")


class TestMTASTS:
    def test_valid(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.OK for c in result.checks
        )

    def test_not_found(self):
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[]):
            result = check_mta_sts("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)


class TestMTASTSExtra:
    def test_bad_dns_version_error(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                with patch(
                    "mailvalidator.checks.mta_sts._parse_dns_record",
                    return_value={"v": "STSv2", "id": "20240101T000000"},
                ):
                    result = check_mta_sts("example.com")
        assert any(
            c.name == "DNS Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_id_error(self):
        dns_record = '"v=STSv1"'
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Record ID (id=)" and c.status == Status.ERROR
            for c in result.checks
        )

    def test_policy_fetch_failure(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=("", "", "connection refused"),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy File" and c.status == Status.ERROR for c in result.checks
        )

    def test_testing_mode_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: testing\nmax_age: 604800\nmx: mail.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_none_mode_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: none\nmax_age: 604800\nmx: mail.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy Mode" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_short_max_age_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: enforce\nmax_age: 3600\nmx: mail.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "max_age" and c.status == Status.WARNING for c in result.checks
        )

    def test_invalid_max_age_error(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = (
            "version: STSv1\nmode: enforce\nmax_age: notanumber\nmx: mail.example.com"
        )
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "max_age" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_max_age_error(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: enforce\nmx: mail.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "max_age" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_mx_entries_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: enforce\nmax_age: 604800"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "MX Entries" and c.status == Status.WARNING for c in result.checks
        )

    def test_multiple_mx_entries(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx1.example.com\nmx: mx2.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        mx_check = next(c for c in result.checks if c.name == "MX Entries")
        assert "mx1.example.com" in mx_check.value
        assert "mx2.example.com" in mx_check.value

    def test_duplicate_mx_entries_warns(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx1.example.com\nmx: mx1.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        mx_check = next(c for c in result.checks if c.name == "MX Entries")
        assert mx_check.status == Status.WARNING
        assert any("duplicate" in d.lower() for d in (mx_check.details or []))

    def test_no_duplicate_mx_entries_ok(self):
        dns_record = '"v=STSv1; id=20240101T000000"'
        policy = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx1.example.com\nmx: mx2.example.com"
        with patch("mailvalidator.checks.mta_sts.resolve", return_value=[dns_record]):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        mx_check = next(c for c in result.checks if c.name == "MX Entries")
        assert mx_check.status == Status.OK


class TestMTASTSCoverage:
    def test_parse_policy_file_multi_mx(self):
        text = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx1.example.com\nmx: mx2.example.com"
        policy = _parse_policy_file(text)
        assert policy["mx"] == ["mx1.example.com", "mx2.example.com"]

    def test_parse_policy_file_skips_blank_lines(self):
        policy = _parse_policy_file("\nmode: enforce\n\nmax_age: 604800\n")
        assert "mode" in policy
        assert "max_age" in policy

    def test_fetch_policy_url_error(self):
        with patch(
            "mailvalidator.checks.mta_sts.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            text, ct, err = _fetch_policy(
                "https://mta-sts.example.com/.well-known/mta-sts.txt"
            )
        assert text == ""
        assert ct == ""
        assert "connection refused" in err

    def test_fetch_policy_generic_exception(self):
        with patch(
            "mailvalidator.checks.mta_sts.urllib.request.urlopen",
            side_effect=RuntimeError("unexpected"),
        ):
            text, ct, err = _fetch_policy(
                "https://mta-sts.example.com/.well-known/mta-sts.txt"
            )
        assert text == ""
        assert "unexpected" in err


class TestMTASTSRemaining:
    def test_fetch_policy_success_path(self):
        mock_response = MagicMock()
        mock_response.read.return_value = b"version: STSv1\nmode: enforce"
        mock_response.headers.get.return_value = "text/plain"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        with patch(
            "mailvalidator.checks.mta_sts.urllib.request.urlopen",
            return_value=mock_response,
        ):
            text, ct, err = _fetch_policy(
                "https://mta-sts.example.com/.well-known/mta-sts.txt"
            )
        assert err == ""
        assert "STSv1" in text
        assert ct == "text/plain"

    def test_validate_policy_mx_as_string_coerced_to_list(self):
        result = MTASTSResult(domain="example.com")
        raw = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
        _validate_policy(
            {
                "version": "STSv1",
                "mode": "enforce",
                "max_age": "604800",
                "mx": "mail.example.com",
            },
            raw,
            result,
        )
        mx_check = next(c for c in result.checks if c.name == "MX Entries")
        assert mx_check.status == Status.OK
        assert "mail.example.com" in mx_check.value


# ---------------------------------------------------------------------------
# M1 — Multiple DNS records
# ---------------------------------------------------------------------------


class TestMTASTSMultipleRecords:
    def test_multiple_records_error(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=AAA"', '"v=STSv1; id=BBB"'],
        ):
            result = check_mta_sts("example.com")
        assert any(c.status == Status.ERROR for c in result.checks)
        assert any("Multiple" in d for c in result.checks for d in c.details)


# ---------------------------------------------------------------------------
# M2 — id= format validation
# ---------------------------------------------------------------------------


class TestMTASTSIdFormat:
    def test_valid_id_ok(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "Record ID (id=)").status
            == Status.OK
        )

    def test_id_with_hyphens_errors(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=2024-01-01"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "Record ID (id=)").status
            == Status.ERROR
        )

    def test_id_too_long_errors(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=[f'"v=STSv1; id={"A" * 33}"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "Record ID (id=)").status
            == Status.ERROR
        )


# ---------------------------------------------------------------------------
# M3 — Content-Type: text/plain
# ---------------------------------------------------------------------------


class TestMTASTSContentType:
    def test_text_plain_no_warning(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert not any(c.name == "Policy File Content-Type" for c in result.checks)

    def test_wrong_content_type_warns(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(_OK_POLICY, "application/octet-stream", ""),
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy File Content-Type" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_empty_content_type_no_warning(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(_OK_POLICY, "", ""),
            ):
                result = check_mta_sts("example.com")
        assert not any(c.name == "Policy File Content-Type" for c in result.checks)


# ---------------------------------------------------------------------------
# M4 — Policy file version: STSv1
# ---------------------------------------------------------------------------


class TestMTASTSPolicyVersion:
    def test_version_present_first_ok(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "Policy Version").status
            == Status.OK
        )

    def test_version_missing_errors(self):
        policy = "mode: enforce\nmax_age: 604800\nmx: mail.example.com"
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "Policy Version").status
            == Status.ERROR
        )

    def test_wrong_version_errors(self):
        policy = "version: STSv2\nmode: enforce\nmax_age: 604800\nmx: mail.example.com"
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "Policy Version").status
            == Status.ERROR
        )

    def test_version_not_first_warns(self):
        policy = "mode: enforce\nversion: STSv1\nmax_age: 604800\nmx: mail.example.com"
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "Policy Version").status
            == Status.WARNING
        )


# ---------------------------------------------------------------------------
# M5 — max_age upper bound
# ---------------------------------------------------------------------------


class TestMTASTSMaxAgeCeiling:
    def test_at_ceiling_ok(self):
        policy = (
            "version: STSv1\nmode: enforce\nmax_age: 31557600\nmx: mail.example.com"
        )
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert next(c for c in result.checks if c.name == "max_age").status == Status.OK

    def test_exceeds_ceiling_warns(self):
        policy = (
            "version: STSv1\nmode: enforce\nmax_age: 99999999\nmx: mail.example.com"
        )
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "max_age").status
            == Status.WARNING
        )


# ---------------------------------------------------------------------------
# M6 — mx entry validation
# ---------------------------------------------------------------------------


class TestMTASTSMxValidation:
    def test_valid_hostname_ok(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "MX Entries").status == Status.OK
        )

    def test_wildcard_ok(self):
        policy = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: *.example.com"
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "MX Entries").status == Status.OK
        )

    def test_invalid_pattern_warns(self):
        policy = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: not_a_hostname!"
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "MX Entries").status
            == Status.WARNING
        )


# ---------------------------------------------------------------------------
# M8 — CRLF line endings
# ---------------------------------------------------------------------------


class TestMTASTSLineEndings:
    def test_crlf_no_warning(self):
        policy = (
            "version: STSv1\r\nmode: enforce\r\nmax_age: 604800\r\nmx: mail.example.com"
        )
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy",
                return_value=(policy, "text/plain", ""),
            ):
                result = check_mta_sts("example.com")
        assert not any(c.name == "Policy File Line Endings" for c in result.checks)

    def test_lf_only_warns(self):
        # _OK_FETCH uses LF-only, so this should trigger the warning.
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert any(
            c.name == "Policy File Line Endings" and c.status == Status.WARNING
            for c in result.checks
        )


# ---------------------------------------------------------------------------
# M9 — v= first tag in DNS record
# ---------------------------------------------------------------------------


class TestMTASTSDnsTagOrdering:
    def test_v_first_ok(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"v=STSv1; id=20240101T000000"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "DNS Version").status
            == Status.OK
        )

    def test_id_before_v_warns(self):
        with patch(
            "mailvalidator.checks.mta_sts.resolve",
            return_value=['"id=20240101T000000; v=STSv1"'],
        ):
            with patch(
                "mailvalidator.checks.mta_sts._fetch_policy", return_value=_OK_FETCH
            ):
                result = check_mta_sts("example.com")
        assert (
            next(c for c in result.checks if c.name == "DNS Version").status
            == Status.WARNING
        )
