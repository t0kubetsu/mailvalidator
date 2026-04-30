"""Post-quantum cryptography (PQC) key exchange readiness check for SMTP/TLS."""

from __future__ import annotations

from quantumvalidator.assessor import assess
from quantumvalidator.models import CheckResult as QVCheckResult
from quantumvalidator.models import QuantumReport
from quantumvalidator.models import Status as QVStatus
from quantumvalidator.models import Verdict

from mailvalidator.models import CheckResult, Status


def _assess_pqc(host: str, port: int, timeout: int = 10) -> QuantumReport:
    """Run a quantumvalidator PQC assessment for *host*:*port*.

    Wraps :func:`quantumvalidator.assessor.assess` and absorbs any unexpected
    exception so a failed probe never crashes the caller.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: TCP port to probe (e.g. 25, 587, 465).
    :type port: int
    :param timeout: Connection timeout in seconds.
    :type timeout: int
    :returns: Populated :class:`~quantumvalidator.models.QuantumReport`.
    :rtype: quantumvalidator.models.QuantumReport
    """
    try:
        return assess(host, port=port, timeout=timeout)
    except Exception as exc:
        report = QuantumReport(
            target=host,
            detected_starttls=None,
            port=port,
            tls_version=None,
            negotiated_group=None,
            verdict=Verdict.UNSAFE,
        )
        report.checks.append(
            QVCheckResult(
                name="connection",
                status=QVStatus.ERROR,
                value=None,
                reason=str(exc),
            )
        )
        return report


def _check_pqc(host: str, port: int, checks: list[CheckResult]) -> None:
    """Probe *host*:*port* for post-quantum hybrid key exchange readiness.

    Calls :func:`_assess_pqc` (which internally runs ``openssl s_client`` with
    PQC hybrid groups advertised) and appends a single
    :class:`~mailvalidator.models.CheckResult` to *checks*.

    Status mapping:

    +---------------------+---------+----------------------------------------+
    | quantumvalidator    | status  | meaning                                |
    +=====================+=========+========================================+
    | SAFE                | GOOD    | PQC hybrid group negotiated            |
    | UNSAFE              | WARNING | No PQC group; classical key exchange   |
    | probe error         | INFO    | openssl unavailable or probe failed    |
    +---------------------+---------+----------------------------------------+

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: SMTP port already in use (25, 587, or 465).
    :type port: int
    :param checks: List to which the new
        :class:`~mailvalidator.models.CheckResult` is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    report = _assess_pqc(host, port)

    error_check = next(
        (c for c in report.checks if c.status == QVStatus.ERROR), None
    )
    if error_check:
        checks.append(
            CheckResult(
                name="PQC Key Exchange",
                status=Status.INFO,
                value="probe unavailable",
                details=[error_check.reason],
            )
        )
        return

    kex_check = next(
        (c for c in report.checks if c.name == "key_exchange"), None
    )

    if report.verdict == Verdict.SAFE:
        details: list[str] = []
        if kex_check and kex_check.standard:
            details = [f"Standard: {kex_check.standard}."]
        checks.append(
            CheckResult(
                name="PQC Key Exchange",
                status=Status.GOOD,
                value=report.negotiated_group or "safe",
                details=details,
            )
        )
    else:
        details = ["No post-quantum hybrid group negotiated."]
        if kex_check:
            details.append(kex_check.reason)
        checks.append(
            CheckResult(
                name="PQC Key Exchange",
                status=Status.WARNING,
                value=report.negotiated_group or "none",
                details=details,
            )
        )
