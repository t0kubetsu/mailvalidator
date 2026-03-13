"""mailcheck CLI – mail server configuration assessment."""

from __future__ import annotations

from typing import Annotated, Optional

import typer

# from . import __version__
from mailcheck.assessor import assess
from mailcheck.checks.bimi import check_bimi
from mailcheck.checks.blacklist import check_blacklist
from mailcheck.checks.dkim import check_dkim
from mailcheck.checks.dmarc import check_dmarc
from mailcheck.checks.mta_sts import check_mta_sts
from mailcheck.checks.mx import check_mx
from mailcheck.checks.smtp import check_smtp
from mailcheck.checks.spf import check_spf
from mailcheck.checks.tlsrpt import check_tlsrpt
from mailcheck.reporter import (
    print_bimi,
    print_blacklist,
    print_dkim,
    print_dmarc,
    print_full_report,
    print_mta_sts,
    print_mx,
    print_smtp,
    print_spf,
    print_tlsrpt,
)
from rich.progress import Progress, SpinnerColumn, TextColumn

__version__ = "0.0.1"
app = typer.Typer(
    name="mailcheck",
    help="Assess mail server configuration: MX, SPF, DKIM, DMARC, BIMI, TLSRPT, MTA-STS, blacklists and more.",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mailcheck {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """mailcheck – Mail server configuration assessment."""


# ── full report ──────────────────────────────────────────────────────────────


@app.command("check")
def cmd_check(
    domain: Annotated[str, typer.Argument(help="Domain name to assess.")],
    dkim_selector: Annotated[
        str, typer.Option("--dkim-selector", "-s", help="DKIM selector.")
    ] = "default",
    bimi_selector: Annotated[
        str, typer.Option("--bimi-selector", help="BIMI selector.")
    ] = "default",
    smtp_port: Annotated[int, typer.Option("--smtp-port", help="SMTP port.")] = 25,
    no_smtp: Annotated[
        bool, typer.Option("--no-smtp", help="Skip SMTP diagnostics.")
    ] = False,
    no_blacklist: Annotated[
        bool, typer.Option("--no-blacklist", help="Skip blacklist check.")
    ] = False,
) -> None:
    """Run all mail server checks for DOMAIN and print a full report."""
    _status_msgs: list[str] = []

    def _cb(msg: str) -> None:
        _status_msgs.append(msg)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)

        def _progress_cb(msg: str) -> None:
            progress.update(task, description=msg)

        report = assess(
            domain,
            dkim_selector=dkim_selector,
            bimi_selector=bimi_selector,
            smtp_port=smtp_port,
            run_smtp=not no_smtp,
            run_blacklist=not no_blacklist,
            progress_cb=_progress_cb,
        )

    print_full_report(report)


# ── individual sub-commands ──────────────────────────────────────────────────


@app.command("mx")
def cmd_mx(domain: Annotated[str, typer.Argument(help="Domain name.")]) -> None:
    """Lookup MX records via authoritative name servers."""
    print_mx(check_mx(domain))


@app.command("smtp")
def cmd_smtp(
    host: Annotated[str, typer.Argument(help="Mail server hostname or IP.")],
    port: Annotated[int, typer.Option("--port", "-p", help="SMTP port.")] = 25,
) -> None:
    """Run SMTP diagnostics against HOST."""
    print_smtp([check_smtp(host, port=port)])


@app.command("spf")
def cmd_spf(domain: Annotated[str, typer.Argument()]) -> None:
    """Look up and validate the SPF record for DOMAIN."""
    print_spf(check_spf(domain))


@app.command("dmarc")
def cmd_dmarc(domain: Annotated[str, typer.Argument()]) -> None:
    """Look up and validate the DMARC record for DOMAIN."""
    print_dmarc(check_dmarc(domain))


@app.command("dkim")
def cmd_dkim(
    domain: Annotated[str, typer.Argument()],
    selector: Annotated[str, typer.Option("--selector", "-s")] = "default",
) -> None:
    """Look up and validate the DKIM record for DOMAIN with SELECTOR."""
    print_dkim(check_dkim(domain, selector=selector))


@app.command("bimi")
def cmd_bimi(
    domain: Annotated[str, typer.Argument()],
    selector: Annotated[str, typer.Option("--selector", "-s")] = "default",
) -> None:
    """Look up and validate the BIMI record for DOMAIN."""
    print_bimi(check_bimi(domain, selector=selector))


@app.command("tlsrpt")
def cmd_tlsrpt(domain: Annotated[str, typer.Argument()]) -> None:
    """Check the SMTP TLSRPT record for DOMAIN."""
    print_tlsrpt(check_tlsrpt(domain))


@app.command("mta-sts")
def cmd_mta_sts(domain: Annotated[str, typer.Argument()]) -> None:
    """Check MTA-STS DNS record and policy file for DOMAIN."""
    print_mta_sts(check_mta_sts(domain))


@app.command("blacklist")
def cmd_blacklist(
    ip: Annotated[str, typer.Argument(help="IP address to check.")],
    workers: Annotated[
        int, typer.Option("--workers", "-w", help="Parallel DNS workers.")
    ] = 50,
) -> None:
    """Check IP against 100+ DNS blacklists / blocklists."""
    print_blacklist(check_blacklist(ip, max_workers=workers))


if __name__ == "__main__":
    app()
