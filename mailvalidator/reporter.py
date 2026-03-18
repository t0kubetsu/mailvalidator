"""Rich-based terminal reporter for mailvalidator results.

All ``print_*`` functions accept the corresponding ``*Result`` dataclass
and render it to the terminal using Rich tables and panels.  The module-
level ``console`` instance can be imported by other modules that need to
write to the same output stream.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mailvalidator.models import (
    BIMIResult,
    BlacklistResult,
    CheckResult,
    DMARCResult,
    DKIMResult,
    FullReport,
    MTASTSResult,
    MXResult,
    SMTPDiagResult,
    SPFResult,
    Status,
    TLSRPTResult,
)

console = Console()

_STATUS_STYLE: dict[Status, tuple[str, str]] = {
    # Generic verdicts
    Status.OK: ("✔", "bold green"),
    Status.WARNING: ("⚠", "bold yellow"),
    Status.ERROR: ("✘", "bold red"),
    Status.INFO: ("ℹ", "bold cyan"),
    Status.NOT_FOUND: ("–", "dim"),
    # TLS-grade verdicts
    Status.GOOD: ("✔", "bold green"),
    Status.SUFFICIENT: ("~", "bold yellow"),
    Status.PHASE_OUT: ("↓", "bold yellow"),
    Status.INSUFFICIENT: ("✘", "bold red"),
    Status.NA: ("·", "dim"),
}


def _status_text(status: Status) -> Text:
    """Return a styled Rich :class:`~rich.text.Text` for a :class:`~mailvalidator.models.Status` value.

    :param status: The status to render.
    :returns: Styled text with icon and status label.
    :rtype: ~rich.text.Text
    """
    icon, style = _STATUS_STYLE.get(status, ("?", "bold magenta"))
    return Text(f"{icon} {status.value}", style=style)


def _checks_table(checks: list[CheckResult]) -> Table:
    """Build a Rich :class:`~rich.table.Table` from a list of check results.

    :param checks: Check results to tabulate.
    :returns: A formatted Rich table ready to print.
    :rtype: ~rich.table.Table
    """
    tbl = Table(show_header=True, header_style="bold blue", expand=True, padding=(0, 1))
    tbl.add_column("Check", style="bold")
    tbl.add_column("Status", justify="center")
    tbl.add_column("Value / Details")

    for c in checks:
        detail = c.value
        if c.details:
            extra = "\n".join(c.details)
            detail = f"{detail}\n{extra}".strip() if detail else extra
        tbl.add_row(c.name, _status_text(c.status), detail)

    return tbl


def print_mx(result: MXResult) -> None:
    """Render MX record lookup results to the terminal.

    :param result: MX check result to display.
    :type result: ~mailvalidator.models.MXResult
    """
    console.print(Panel(f"[bold]MX Records[/bold] – {result.domain}", style="blue"))
    if result.authoritative_ns:
        console.print(
            f"  [dim]Authoritative NS:[/dim] {', '.join(result.authoritative_ns)}"
        )
    console.print(_checks_table(result.checks))


def print_smtp(results: list[SMTPDiagResult]) -> None:
    """Render SMTP diagnostic results for one or more mail servers.

    :param results: List of per-server SMTP diagnostic results.
    :type results: list[~mailvalidator.models.SMTPDiagResult]
    """
    for r in results:
        console.print(
            Panel(f"[bold]SMTP Diagnostics[/bold] – {r.host}:{r.port}", style="blue")
        )
        console.print(_checks_table(r.checks))


def print_dkim(result: DKIMResult) -> None:
    """Render DKIM base-node check results to the terminal.

    :param result: DKIM check result to display.
    :type result: ~mailvalidator.models.DKIMResult
    """
    console.print(
        Panel(f"[bold]DKIM[/bold] – _domainkey.{result.domain}", style="blue")
    )
    console.print(_checks_table(result.checks))


def print_bimi(result: BIMIResult) -> None:
    """Render BIMI record validation results to the terminal.

    :param result: BIMI check result to display.
    :type result: ~mailvalidator.models.BIMIResult
    """
    console.print(
        Panel(f"[bold]BIMI[/bold] – default._bimi.{result.domain}", style="blue")
    )
    console.print(_checks_table(result.checks))


def print_tlsrpt(result: TLSRPTResult) -> None:
    """Render TLSRPT record validation results to the terminal.

    :param result: TLSRPT check result to display.
    :type result: ~mailvalidator.models.TLSRPTResult
    """
    console.print(
        Panel(f"[bold]TLSRPT[/bold] – _smtp._tls.{result.domain}", style="blue")
    )
    console.print(_checks_table(result.checks))


def print_blacklist(result: BlacklistResult) -> None:
    """Render DNS blacklist check results to the terminal.

    :param result: Blacklist check result to display.
    :type result: ~mailvalidator.models.BlacklistResult
    """
    console.print(
        Panel(f"[bold]Blacklist / Blocklist Check[/bold] – {result.ip}", style="blue")
    )
    summary = f"Checked {result.total_checked} lists"
    if result.listed_on:
        summary += f" | [bold red]Listed on {len(result.listed_on)}[/bold red]"
    else:
        summary += " | [bold green]Clean[/bold green]"
    console.print(f"  {summary}")
    console.print(_checks_table(result.checks))


def print_spf(result: SPFResult) -> None:
    """Render SPF record validation results to the terminal.

    :param result: SPF check result to display.
    :type result: ~mailvalidator.models.SPFResult
    """
    console.print(Panel(f"[bold]SPF[/bold] – {result.domain}", style="blue"))
    console.print(_checks_table(result.checks))


def print_dmarc(result: DMARCResult) -> None:
    """Render DMARC record validation results to the terminal.

    :param result: DMARC check result to display.
    :type result: ~mailvalidator.models.DMARCResult
    """
    console.print(Panel(f"[bold]DMARC[/bold] – _dmarc.{result.domain}", style="blue"))
    console.print(_checks_table(result.checks))


def print_mta_sts(result: MTASTSResult) -> None:
    """Render MTA-STS record and policy validation results to the terminal.

    :param result: MTA-STS check result to display.
    :type result: ~mailvalidator.models.MTASTSResult
    """
    console.print(Panel(f"[bold]MTA-STS[/bold] – {result.domain}", style="blue"))
    console.print(_checks_table(result.checks))


def print_full_report(report: FullReport) -> None:
    """Render the complete :class:`~mailvalidator.models.FullReport` to the terminal.

    Sections are printed in a fixed order that mirrors the check sequence
    in :func:`~mailvalidator.assessor.assess`.  Sections whose result is ``None``
    are silently skipped.
    """
    console.rule(f"[bold cyan]Mail Server Report: {report.domain}[/bold cyan]")

    if report.mx:
        print_mx(report.mx)
    if report.smtp:
        print_smtp(report.smtp)
    if report.spf:
        print_spf(report.spf)
    if report.dmarc:
        print_dmarc(report.dmarc)
    if report.dkim:
        print_dkim(report.dkim)
    if report.bimi:
        print_bimi(report.bimi)
    if report.tlsrpt:
        print_tlsrpt(report.tlsrpt)
    if report.mta_sts:
        print_mta_sts(report.mta_sts)
    if report.blacklist:
        print_blacklist(report.blacklist)

    console.rule("[dim]End of Report[/dim]")
