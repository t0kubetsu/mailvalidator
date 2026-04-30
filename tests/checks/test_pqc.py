"""Tests for mailvalidator.checks.smtp._pqc."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.smtp import _assess_pqc, _check_pqc
from mailvalidator.models import Status

from quantumvalidator.models import (
    CheckResult as QVCheckResult,
    QuantumReport,
    Status as QVStatus,
    Verdict,
)


def _make_report(
    verdict: Verdict,
    negotiated_group: str | None = None,
    tls_version: str | None = "TLSv1.3",
    checks: list | None = None,
) -> QuantumReport:
    return QuantumReport(
        target="mail.example.com",
        detected_starttls="smtp",
        port=25,
        tls_version=tls_version,
        negotiated_group=negotiated_group,
        verdict=verdict,
        checks=checks or [],
    )


def _qv_kex(
    status: QVStatus,
    value: str | None,
    reason: str,
    standard: str | None = None,
) -> QVCheckResult:
    return QVCheckResult(
        name="key_exchange", status=status, value=value, reason=reason, standard=standard
    )


def _qv_error(reason: str) -> QVCheckResult:
    return QVCheckResult(
        name="connection", status=QVStatus.ERROR, value=None, reason=reason
    )


class TestAssessPqc:
    def test_returns_report_on_success(self):
        report = _make_report(Verdict.SAFE, negotiated_group="X25519MLKEM768")
        with patch("mailvalidator.checks.smtp._pqc.assess", return_value=report) as mock:
            result = _assess_pqc("mail.example.com", 25)
        mock.assert_called_once_with("mail.example.com", port=25, timeout=10)
        assert result is report

    def test_absorbs_exception_returns_error_report(self):
        with patch(
            "mailvalidator.checks.smtp._pqc.assess",
            side_effect=RuntimeError("openssl not found"),
        ):
            result = _assess_pqc("mail.example.com", 25)
        assert result.verdict == Verdict.UNSAFE
        assert len(result.checks) == 1
        assert result.checks[0].status == QVStatus.ERROR
        assert "openssl not found" in result.checks[0].reason

    def test_passes_port_to_assess(self):
        report = _make_report(Verdict.UNSAFE)
        with patch("mailvalidator.checks.smtp._pqc.assess", return_value=report) as mock:
            _assess_pqc("mx1.example.com", 587)
        mock.assert_called_once_with("mx1.example.com", port=587, timeout=10)


class TestCheckPqcSafe:
    def test_good_status_with_standard(self):
        checks: list = []
        report = _make_report(
            Verdict.SAFE,
            negotiated_group="X25519MLKEM768",
            checks=[
                _qv_kex(
                    QVStatus.PASS,
                    "X25519MLKEM768",
                    "PQC hybrid group negotiated (0x11ec).",
                    "CNSA 2.0, BSI TR-02102-2",
                )
            ],
        )
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.name == "PQC Key Exchange"
        assert cr.status == Status.GOOD
        assert cr.value == "X25519MLKEM768"
        assert any("CNSA" in d for d in cr.details)

    def test_good_status_no_standard(self):
        checks: list = []
        report = _make_report(
            Verdict.SAFE,
            negotiated_group="X25519MLKEM768",
            checks=[_qv_kex(QVStatus.PASS, "X25519MLKEM768", "PQC group.", standard=None)],
        )
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.status == Status.GOOD
        assert cr.details == []

    def test_good_status_no_kex_check_in_report(self):
        checks: list = []
        report = _make_report(Verdict.SAFE, negotiated_group="X25519MLKEM768", checks=[])
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.status == Status.GOOD
        assert cr.value == "X25519MLKEM768"

    def test_good_status_none_group_fallback(self):
        checks: list = []
        report = _make_report(Verdict.SAFE, negotiated_group=None, checks=[])
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.status == Status.GOOD
        assert cr.value == "safe"


class TestCheckPqcUnsafe:
    def test_warning_status_with_kex_reason(self):
        checks: list = []
        report = _make_report(
            Verdict.UNSAFE,
            negotiated_group="x25519",
            checks=[
                _qv_kex(
                    QVStatus.FAIL,
                    "x25519",
                    "No PQC hybrid group; got x25519. Enable X25519MLKEM768.",
                )
            ],
        )
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.name == "PQC Key Exchange"
        assert cr.status == Status.WARNING
        assert cr.value == "x25519"
        assert "No post-quantum hybrid group negotiated." in cr.details
        assert any("X25519MLKEM768" in d for d in cr.details)

    def test_warning_none_group(self):
        checks: list = []
        report = _make_report(Verdict.UNSAFE, negotiated_group=None, checks=[])
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.status == Status.WARNING
        assert cr.value == "none"

    def test_warning_no_kex_check(self):
        checks: list = []
        report = _make_report(Verdict.UNSAFE, negotiated_group="x25519", checks=[])
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.status == Status.WARNING
        assert cr.details == ["No post-quantum hybrid group negotiated."]


class TestCheckPqcError:
    def test_info_status_on_error(self):
        checks: list = []
        report = _make_report(
            Verdict.UNSAFE,
            checks=[_qv_error("openssl not found on PATH.")],
        )
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        cr = checks[0]
        assert cr.name == "PQC Key Exchange"
        assert cr.status == Status.INFO
        assert cr.value == "probe unavailable"
        assert "openssl not found on PATH." in cr.details

    def test_info_carries_timeout_reason(self):
        checks: list = []
        report = _make_report(
            Verdict.UNSAFE,
            checks=[_qv_error("Connection timed out.")],
        )
        with patch("mailvalidator.checks.smtp._pqc._assess_pqc", return_value=report):
            _check_pqc("mail.example.com", 25, checks)
        assert "Connection timed out." in checks[0].details
