"""Tests for mailvalidator/checks/spf.py."""

from __future__ import annotations

from unittest.mock import patch


from mailvalidator.checks.spf import check_spf
from mailvalidator.models import Status


class TestSPF:
    def test_fail_all_ok(self):
        with patch(
            "mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ip4:1.2.3.4 -all"']
        ):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK
        assert "-all" in policy.value

    def test_softfail_all_ok(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ~all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK

    def test_neutral_all_warning(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ?all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING

    def test_plus_all_error(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=['"v=spf1 +all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.ERROR

    def test_missing_all_implies_neutral(self):
        with patch(
            "mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ip4:1.2.3.4"']
        ):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING
        assert "neutral" in " ".join(policy.details).lower()

    def test_not_found(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=[]):
            result = check_spf("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_multiple_spf_records_error(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 -all"', '"v=spf1 ~all"'],
        ):
            result = check_spf("example.com")
        assert any(
            c.status == Status.ERROR and "Multiple" in c.name for c in result.checks
        )

    def test_ptr_deprecation_warned(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ptr -all"']):
            result = check_spf("example.com")
        assert any(
            c.name == "ptr Mechanism" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_include_resolved_and_shown(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:_spf.protonmail.ch ~all"']
            if domain == "_spf.protonmail.ch":
                return ['"v=spf1 ip4:185.70.40.0/24 ip4:185.70.41.0/24 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert resolution.status == Status.OK
        assert "_spf.protonmail.ch" in " ".join(resolution.details)

    def test_include_lookup_count_recursive(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:_spf.protonmail.ch -all"']
            if domain == "_spf.protonmail.ch":
                return ['"v=spf1 a:mail.protonmail.ch ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")

    def test_ptr_counts_as_lookup(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ptr -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")

    def test_ip4_ip6_not_counted_as_lookups(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all"'],
        ):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("0/")

    def test_include_missing_record_warns(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:missing.example.com -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert resolution.status == Status.WARNING

    def test_include_loop_handled(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:a.example.com -all"']
            if domain == "a.example.com":
                return ['"v=spf1 include:b.example.com -all"']
            if domain == "b.example.com":
                return ['"v=spf1 include:a.example.com -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        assert result is not None

    def test_macro_in_include_not_followed(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 include:%{d}._spf.example.com -all"'],
        ):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("macro" in detail.lower() for detail in resolution.details)

    def test_redirect_is_followed(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 ip4:10.0.0.0/8 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK

    def test_redirect_lookup_counted(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 mx -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")


class TestSPFCoverage:
    def test_bad_version_tag_error(self):
        from mailvalidator.checks.spf import _validate_spf
        from mailvalidator.models import SPFResult

        result = SPFResult(domain="example.com")
        _validate_spf("v=spf2 -all", "example.com", result)
        assert any(
            c.name == "SPF Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_redirect_macro_noted_not_followed(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 redirect=%{d}._spf.example.com"'],
        ):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("macro" in detail.lower() for detail in resolution.details)

    def test_redirect_with_no_all_in_target_warns(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING

    def test_lookup_count_exceeds_limit(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                includes = " ".join(f"include:s{i}.example.net" for i in range(11))
                return [f'"v=spf1 {includes} -all"']
            return ['"v=spf1 ip4:1.2.3.4 -all"']

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.status == Status.ERROR
