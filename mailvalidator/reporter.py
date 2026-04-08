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
    DKIMResult,
    DMARCResult,
    DNSSECResult,
    FullReport,
    MTASTSResult,
    MXResult,
    SMTPDiagResult,
    SPFResult,
    Status,
    TLSRPTResult,
)
from mailvalidator.verdict import VerdictAction, VerdictSeverity, extract_verdict_actions

console = Console(record=True)

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


_FORMAT_BY_EXT: dict[str, str] = {
    ".txt": "text",
    ".text": "text",
    ".svg": "svg",
    ".html": "html",
    ".htm": "html",
}


def save_report(path: str) -> None:
    """Save the recorded console output to *path*.

    The export format is inferred from the file extension:

    +------------------+--------+
    | Extension        | Format |
    +==================+========+
    | ``.txt`` / ``.text`` | plain text |
    | ``.svg``        | SVG image |
    | ``.html`` / ``.htm`` | HTML page |
    +------------------+--------+

    Must be called **after** :func:`print_full_report` because Rich only
    captures output when :class:`~rich.console.Console` is created with
    ``record=True``, which is already set on the module-level
    :data:`console` instance.

    :param path: Destination file path, e.g. ``"report.svg"``.
    :type path: str
    :raises ValueError: If the file extension is not one of the supported
        values listed above.
    :raises OSError: If the file cannot be written.
    """
    import os

    ext = os.path.splitext(path)[1].lower()
    fmt = _FORMAT_BY_EXT.get(ext)
    if fmt is None:
        raise ValueError(
            f"Unsupported export format '{ext or '(none)'}'. "
            "Use a .txt, .svg, .html, or .htm extension."
        )
    if fmt == "text":
        console.save_text(path, clear=False)
    elif fmt == "svg":
        console.save_svg(path, clear=False)
    else:
        console.save_html(path, clear=False)


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


_SMTP_SECTIONS: list[tuple[str, str]] = [
    ("Protocol", "blue"),
    ("TLS", "cyan"),
    ("Certificate", "green"),
    ("DNS", "magenta"),
]


def print_smtp(results: list[SMTPDiagResult]) -> None:
    """Render SMTP diagnostic results for one or more mail servers.

    Checks are grouped into four sections (Protocol, TLS, Certificate, DNS)
    when section metadata is present.  Falls back to a single flat table for
    results produced without section tags.

    :param results: List of per-server SMTP diagnostic results.
    :type results: list[~mailvalidator.models.SMTPDiagResult]
    """
    for r in results:
        console.print(
            Panel(f"[bold]SMTP Diagnostics[/bold] – {r.host}:{r.port}", style="blue")
        )

        # Group by section
        sectioned: dict[str, list[CheckResult]] = {}
        unsectioned: list[CheckResult] = []
        for cr in r.checks:
            if cr.section:
                sectioned.setdefault(cr.section, []).append(cr)
            else:
                unsectioned.append(cr)

        if sectioned:
            for section_name, style in _SMTP_SECTIONS:
                group = sectioned.get(section_name, [])
                if not group:
                    continue
                console.print(Panel(f"[bold]{section_name}[/bold]", style=style, expand=True))
                console.print(_checks_table(group))
            # Emit any checks with unrecognised section names
            for sname, group in sectioned.items():
                if sname not in {s for s, _ in _SMTP_SECTIONS}:
                    console.print(Panel(f"[bold]{sname}[/bold]", style="white", expand=True))
                    console.print(_checks_table(group))
            if unsectioned:
                console.print(_checks_table(unsectioned))
        else:
            # No section metadata: flat table (backward-compatible)
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


def print_dnssec_domain(result: DNSSECResult) -> None:
    """Render DNSSEC email-domain check results to the terminal.

    :param result: DNSSEC check result for the email address domain.
    :type result: ~mailvalidator.models.DNSSECResult
    """
    console.print(
        Panel(f"[bold]DNSSEC – Email Domain[/bold] – {result.domain}", style="blue")
    )
    console.print(_checks_table(result.checks))


def print_dnssec_mx(result: DNSSECResult) -> None:
    """Render DNSSEC MX-domain check results to the terminal.

    :param result: DNSSEC check result for the MX server domain(s).
    :type result: ~mailvalidator.models.DNSSECResult
    """
    console.print(
        Panel(
            f"[bold]DNSSEC – Mail Server Domain(s)[/bold] – {result.domain}",
            style="blue",
        )
    )
    console.print(_checks_table(result.checks))


def print_verdict(actions: list[VerdictAction]) -> None:
    """Render the prioritised security verdict panel to the terminal.

    Displays a colour-coded table of actionable items sorted from most to
    least urgent (``CRITICAL`` → ``HIGH`` → ``MEDIUM``).  Called by
    :func:`print_full_report` when there is at least one action to show.

    :param actions: Deduplicated, severity-sorted action list from
        :func:`~mailvalidator.verdict.extract_verdict_actions`.
    :type actions: list[~mailvalidator.verdict.VerdictAction]
    """
    _SEV_STYLE: dict[VerdictSeverity, tuple[str, str]] = {
        VerdictSeverity.CRITICAL: ("bold red", "✘ CRITICAL"),
        VerdictSeverity.HIGH: ("bold yellow", "⚠ HIGH"),
        VerdictSeverity.MEDIUM: ("bold cyan", "· MEDIUM"),
    }
    tbl = Table(show_header=True, header_style="bold red", expand=True, padding=(0, 1))
    tbl.add_column("Priority", justify="center", no_wrap=True)
    tbl.add_column("Action")
    for action in actions:
        style, label = _SEV_STYLE[action.severity]
        tbl.add_row(Text(label, style=style), action.text)
    console.print(
        Panel(
            "[bold red]Security Verdict[/bold red] – Prioritised Actions",
            style="red",
        )
    )
    console.print(tbl)


def print_full_report(report: FullReport) -> None:
    """Render the complete :class:`~mailvalidator.models.FullReport` to the terminal.

    Sections are printed in a fixed order that mirrors the check sequence
    in :func:`~mailvalidator.assessor.assess`.  Sections whose result is ``None``
    are silently skipped.
    """
    console.rule(f"[bold cyan]Mail Server Report: {report.domain}[/bold cyan]")

    if report.mx:
        print_mx(report.mx)
    if report.dnssec_domain:
        print_dnssec_domain(report.dnssec_domain)
    if report.dnssec_mx:
        print_dnssec_mx(report.dnssec_mx)
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

    actions = extract_verdict_actions(report)
    if actions:
        print_verdict(actions)

    console.rule("[dim]End of Report[/dim]")
