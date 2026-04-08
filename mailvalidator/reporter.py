"""Rich-based terminal reporter for mailvalidator results.

All ``print_*`` functions accept the corresponding ``*Result`` dataclass
and render it to the terminal using Rich tables and panels.  The module-
level ``console`` instance can be imported by other modules that need to
write to the same output stream.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
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
from mailvalidator.verdict import (
    Grade,
    VerdictAction,
    VerdictSeverity,
    calculate_grade,
    extract_verdict_actions,
)

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
    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="dim",
        expand=False,
        padding=(0, 1),
    )
    tbl.add_column("Check", style="bold")
    tbl.add_column("Status", justify="center")
    tbl.add_column("Value / Details")

    for c in checks:
        if c.details:
            extra = "\n".join(f"[dim]{d}[/dim]" for d in c.details)
            detail = f"{c.value}\n{extra}" if c.value else extra
        else:
            detail = c.value or ""
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
    table = _checks_table(result.checks)
    if result.authoritative_ns:
        ns_line = Text(
            f"  Authoritative NS: {', '.join(result.authoritative_ns)}",
            style="dim",
        )
        content = Group(ns_line, table)
    else:
        content = Group(table)
    console.print(
        Panel(
            content,
            title=f"[bold]MX Records[/bold] – {result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


_SMTP_SECTIONS: list[tuple[str, str]] = [
    ("Protocol", "bright_white"),
    ("TLS", "bright_white"),
    ("Certificate", "bright_white"),
    ("DNS", "bright_white"),
]


def print_smtp(results: list[SMTPDiagResult]) -> None:
    """Render SMTP diagnostic results for one or more mail servers.

    Checks are grouped into four inner panels (Protocol, TLS, Certificate, DNS)
    when section metadata is present, all nested inside an outer server panel.
    Falls back to a single flat table for results produced without section tags.

    :param results: List of per-server SMTP diagnostic results.
    :type results: list[~mailvalidator.models.SMTPDiagResult]
    """
    for r in results:
        # Group by section
        sectioned: dict[str, list[CheckResult]] = {}
        unsectioned: list[CheckResult] = []
        for cr in r.checks:
            if cr.section:
                sectioned.setdefault(cr.section, []).append(cr)
            else:
                unsectioned.append(cr)

        if sectioned:
            inner_panels: list[Panel] = []
            for section_name, style in _SMTP_SECTIONS:
                group = sectioned.get(section_name, [])
                if not group:
                    continue
                inner_panels.append(
                    Panel(
                        _checks_table(group),
                        title=f"[bold]{section_name}[/bold]",
                        style=style,
                        padding=(0, 1),
                    )
                )
            # Emit any checks with unrecognised section names
            known = {s for s, _ in _SMTP_SECTIONS}
            for sname, group in sectioned.items():
                if sname not in known:
                    inner_panels.append(
                        Panel(
                            _checks_table(group),
                            title=f"[bold]{sname}[/bold]",
                            style="white",
                            padding=(0, 1),
                        )
                    )
            if unsectioned:
                inner_panels.append(_checks_table(unsectioned))
            content = Group(*inner_panels)
        else:
            # No section metadata: flat table (backward-compatible)
            content = Group(_checks_table(r.checks))

        console.print(
            Panel(
                content,
                title=f"[bold]SMTP Diagnostics[/bold] – {r.host}:{r.port}",
                style="white",
                padding=(0, 1),
            )
        )


def print_dkim(result: DKIMResult) -> None:
    """Render DKIM base-node check results to the terminal.

    :param result: DKIM check result to display.
    :type result: ~mailvalidator.models.DKIMResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]DKIM[/bold] – _domainkey.{result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


def print_bimi(result: BIMIResult) -> None:
    """Render BIMI record validation results to the terminal.

    :param result: BIMI check result to display.
    :type result: ~mailvalidator.models.BIMIResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]BIMI[/bold] – default._bimi.{result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


def print_tlsrpt(result: TLSRPTResult) -> None:
    """Render TLSRPT record validation results to the terminal.

    :param result: TLSRPT check result to display.
    :type result: ~mailvalidator.models.TLSRPTResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]TLSRPT[/bold] – _smtp._tls.{result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


def print_blacklist(result: BlacklistResult) -> None:
    """Render DNS blacklist check results to the terminal.

    :param result: Blacklist check result to display.
    :type result: ~mailvalidator.models.BlacklistResult
    """
    summary = f"  Checked {result.total_checked} lists"
    if result.listed_on:
        summary += f" | [bold red]Listed on {len(result.listed_on)}[/bold red]"
    else:
        summary += " | [bold green]Clean[/bold green]"
    console.print(
        Panel(
            Group(Text.from_markup(summary), _checks_table(result.checks)),
            title=f"[bold]Blacklist / Blocklist Check[/bold] – {result.ip}",
            style="white",
            padding=(0, 1),
        )
    )


def print_spf(result: SPFResult) -> None:
    """Render SPF record validation results to the terminal.

    :param result: SPF check result to display.
    :type result: ~mailvalidator.models.SPFResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]SPF[/bold] – {result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


def print_dmarc(result: DMARCResult) -> None:
    """Render DMARC record validation results to the terminal.

    :param result: DMARC check result to display.
    :type result: ~mailvalidator.models.DMARCResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]DMARC[/bold] – _dmarc.{result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


def print_mta_sts(result: MTASTSResult) -> None:
    """Render MTA-STS record and policy validation results to the terminal.

    :param result: MTA-STS check result to display.
    :type result: ~mailvalidator.models.MTASTSResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]MTA-STS[/bold] – {result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


def print_dnssec_domain(result: DNSSECResult) -> None:
    """Render DNSSEC email-domain check results to the terminal.

    :param result: DNSSEC check result for the email address domain.
    :type result: ~mailvalidator.models.DNSSECResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]DNSSEC – Email Domain[/bold] – {result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


def print_dnssec_mx(result: DNSSECResult) -> None:
    """Render DNSSEC MX-domain check results to the terminal.

    :param result: DNSSEC check result for the MX server domain(s).
    :type result: ~mailvalidator.models.DNSSECResult
    """
    console.print(
        Panel(
            _checks_table(result.checks),
            title=f"[bold]DNSSEC – Mail Server Domain(s)[/bold] – {result.domain}",
            style="white",
            padding=(0, 1),
        )
    )


_GRADE_STYLE: dict[str, str] = {
    "A+": "bold bright_green",
    "A": "bold green",
    "B": "bold yellow",
    "C": "bold yellow",
    "D": "bold red",
    "F": "bold bright_red",
}

_SEVERITY_STYLE: dict[VerdictSeverity, str] = {
    VerdictSeverity.CRITICAL: "bold red",
    VerdictSeverity.HIGH: "bold yellow",
    VerdictSeverity.MEDIUM: "bold cyan",
}


def _grade_text(grade: Grade) -> Text:
    """Return a styled Rich :class:`~rich.text.Text` for the verdict panel title.

    Assembles "Security Verdict", the letter grade (coloured by grade), and
    the rationale into a single :class:`~rich.text.Text`.

    :param grade: Grade produced by :func:`~mailvalidator.verdict.calculate_grade`.
    :returns: Styled text showing the letter grade and rationale.
    :rtype: ~rich.text.Text
    """
    style = _GRADE_STYLE.get(grade.letter, "bold white")
    return Text.assemble(
        ("Security Verdict  ", "bold white"),
        (grade.letter, style),
        ("  ", ""),
        (grade.rationale, "dim"),
    )


def print_verdict(actions: list[VerdictAction], grade: Grade | None = None) -> None:
    """Render the prioritised security verdict panel to the terminal.

    Displays a colour-coded table of actionable items inside a Rich panel
    whose border reflects the overall grade.  Items are sorted from most to
    least urgent (``CRITICAL`` → ``HIGH`` → ``MEDIUM``).
    Called by :func:`print_full_report`.

    :param actions: Deduplicated, severity-sorted action list from
        :func:`~mailvalidator.verdict.extract_verdict_actions`.
    :type actions: list[~mailvalidator.verdict.VerdictAction]
    :param grade: Optional grade computed by
        :func:`~mailvalidator.verdict.calculate_grade`.
    :type grade: ~mailvalidator.verdict.Grade or None
    """
    border_colour = "white"
    title: Text | str = "Security Verdict"
    if grade is not None:
        title = _grade_text(grade)
        border_colour = _GRADE_STYLE.get(grade.letter, "bold white").split()[-1]

    tbl = Table(
        box=box.SIMPLE, show_header=True, header_style="bold white", expand=True
    )
    tbl.add_column("Priority", style="bold", min_width=10, no_wrap=True)
    tbl.add_column("Action")

    for action in actions:
        sev_style = _SEVERITY_STYLE[action.severity]
        tbl.add_row(Text(action.severity.value, style=sev_style), action.text)

    if not actions:
        tbl.add_row(
            Text("PASS", style="bold green"),
            "No issues found — mail server configuration is excellent.",
        )

    console.print(
        Panel(
            tbl,
            title=title,
            border_style=border_colour,
            expand=False,
            padding=(0, 1),
        )
    )
    console.print()


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
    grade = calculate_grade(actions)
    print_verdict(actions, grade)

    console.rule("[dim]End of Report[/dim]")
