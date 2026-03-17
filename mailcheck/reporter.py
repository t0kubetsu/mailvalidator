"""Rich-based terminal reporter for mailcheck results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mailcheck.models import (
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
    icon, style = _STATUS_STYLE.get(status, ("?", "bold magenta"))
    return Text(f"{icon} {status.value}", style=style)


def _checks_table(checks: list[CheckResult]) -> Table:
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
    console.print(Panel(f"[bold]MX Records[/bold] – {result.domain}", style="blue"))
    if result.authoritative_ns:
        console.print(
            f"  [dim]Authoritative NS:[/dim] {', '.join(result.authoritative_ns)}"
        )
    console.print(_checks_table(result.checks))


def print_smtp(results: list[SMTPDiagResult]) -> None:
    for r in results:
        console.print(
            Panel(f"[bold]SMTP Diagnostics[/bold] – {r.host}:{r.port}", style="blue")
        )
        console.print(_checks_table(r.checks))


def print_dkim(result: DKIMResult) -> None:
    console.print(
        Panel(
            f"[bold]DKIM[/bold] – _domainkey.{result.domain}",
            style="blue",
        )
    )
    console.print(_checks_table(result.checks))


def print_bimi(result: BIMIResult) -> None:
    console.print(
        Panel(f"[bold]BIMI[/bold] – default._bimi.{result.domain}", style="blue")
    )
    console.print(_checks_table(result.checks))


def print_tlsrpt(result: TLSRPTResult) -> None:
    console.print(
        Panel(f"[bold]TLSRPT[/bold] – _smtp._tls.{result.domain}", style="blue")
    )
    console.print(_checks_table(result.checks))


def print_blacklist(result: BlacklistResult) -> None:
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
    console.print(Panel(f"[bold]SPF[/bold] – {result.domain}", style="blue"))
    console.print(_checks_table(result.checks))


def print_dmarc(result: DMARCResult) -> None:
    console.print(Panel(f"[bold]DMARC[/bold] – _dmarc.{result.domain}", style="blue"))
    console.print(_checks_table(result.checks))


def print_mta_sts(result: MTASTSResult) -> None:
    console.print(Panel(f"[bold]MTA-STS[/bold] – {result.domain}", style="blue"))
    console.print(_checks_table(result.checks))


def print_full_report(report: FullReport) -> None:
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
