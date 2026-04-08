"""mailvalidator CLI – mail server configuration assessment.

Sub-commands
------------
check       Run all checks for a domain and print a full report.
mx          Look up MX records.
smtp        Run SMTP diagnostics against a mail server.
spf         Validate the SPF record.
dmarc       Validate the DMARC record.
dkim        Check the DKIM base node (_domainkey.<domain>).
bimi        Validate the BIMI record.
tlsrpt      Check the SMTP TLS Reporting record.
mta-sts     Check the MTA-STS DNS record and policy file.
blacklist   Check an IP address against 100+ DNS blacklists.

Usage example::

    mailvalidator check example.com
    mailvalidator smtp mx1.example.com --port 587
    mailvalidator blacklist 203.0.113.42
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import re
from typing import Annotated, Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from mailvalidator import __version__
from mailvalidator.assessor import assess
from mailvalidator.checks.bimi import check_bimi
from mailvalidator.checks.blacklist import check_blacklist
from mailvalidator.checks.dkim import check_dkim
from mailvalidator.checks.dmarc import check_dmarc
from mailvalidator.checks.dnssec import check_dnssec_domain, check_dnssec_mx
from mailvalidator.checks.mta_sts import check_mta_sts
from mailvalidator.checks.mx import check_mx
from mailvalidator.checks.smtp import check_smtp
from mailvalidator.checks.spf import check_spf
from mailvalidator.checks.tlsrpt import check_tlsrpt
from mailvalidator.reporter import (
    print_bimi,
    print_blacklist,
    print_dkim,
    print_dmarc,
    print_dnssec_domain,
    print_dnssec_mx,
    print_full_report,
    print_mta_sts,
    print_mx,
    print_smtp,
    print_spf,
    print_tlsrpt,
    save_report,
)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="mailvalidator",
    help="Assess mail server configuration: MX, SPF, DKIM, DMARC, BIMI, TLSRPT, MTA-STS, blacklists and more.",
    add_completion=False,
)

# ---------------------------------------------------------------------------
# Input validators
# ---------------------------------------------------------------------------

# A valid fully-qualified domain name: at least two labels, each 1-63 chars,
# optional trailing dot.  Single-label names (e.g. "localhost") are rejected.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}\.?$"
)

# A hostname or bare IP: accepts single-label names (e.g. "mailserver") as
# well as fully-qualified hostnames, because `smtp` targets need not be FQDNs.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"(?:[a-zA-Z0-9-]{1,63})\.?$"
)


def _print_json(obj: object) -> None:
    """Serialise a dataclass *obj* to stdout as pretty-printed JSON."""
    typer.echo(json.dumps(dataclasses.asdict(obj), indent=2))  # type: ignore[call-overload]


def _validate_domain(value: str) -> str:
    """Reject input that is not a valid domain name.

    Requires at least two DNS labels (e.g. ``"example.com"``).
    Single-label names such as ``"localhost"`` are rejected.

    :param value: Raw string from the CLI argument.
    :returns: The validated domain string unchanged.
    :rtype: str
    :raises typer.BadParameter: If *value* is not a valid domain name.
    """
    if not _DOMAIN_RE.match(value):
        raise typer.BadParameter(f"'{value}' is not a valid domain name")
    return value


def _validate_host(value: str) -> str:
    """Accept a bare IPv4/IPv6 address or a hostname / domain name.

    Unlike :func:`_validate_domain`, single-label names (e.g.
    ``"mailserver"``) are permitted because SMTP targets need not be FQDNs.

    :param value: Raw string from the CLI argument.
    :returns: The validated host string unchanged.
    :rtype: str
    :raises typer.BadParameter: If *value* is neither a valid IP address
        nor a valid hostname.
    """
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(value):
        raise typer.BadParameter(f"'{value}' is not a valid IP address or hostname")
    return value


def _validate_ip(value: str) -> str:
    """Reject input that is not a valid IPv4 or IPv6 address.

    :param value: Raw string from the CLI argument.
    :returns: The validated IP address string unchanged.
    :rtype: str
    :raises typer.BadParameter: If *value* is not a valid IP address.
    """
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise typer.BadParameter(f"'{value}' is not a valid IP address")


# ---------------------------------------------------------------------------
# App-level callback (--version flag)
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mailvalidator {__version__}")
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
    """mailvalidator – Mail server configuration assessment."""


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


@app.command("check")
def cmd_check(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name to assess.", callback=_validate_domain),
    ],
    smtp_port: Annotated[
        int,
        typer.Option("--smtp-port", help="SMTP port to probe."),
    ] = 25,
    no_smtp: Annotated[
        bool,
        typer.Option("--no-smtp", help="Skip SMTP diagnostics."),
    ] = False,
    no_blacklist: Annotated[
        bool,
        typer.Option("--no-blacklist", help="Skip DNS blacklist check."),
    ] = False,
    no_dnssec: Annotated[
        bool,
        typer.Option("--no-dnssec", help="Skip DNSSEC chain-of-trust checks."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "Save the report to a file. "
                "Format is inferred from the extension: "
                ".txt for plain text, .svg for SVG, .html for HTML."
            ),
        ),
    ] = None,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Run all mail server checks for DOMAIN and print a full report."""
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
            smtp_port=smtp_port,
            run_smtp=not no_smtp,
            run_blacklist=not no_blacklist,
            run_dnssec=not no_dnssec,
            progress_cb=_progress_cb,
        )

    if as_json:
        _print_json(report)
        return

    print_full_report(report)

    if output:
        try:
            save_report(output)
            typer.echo(f"Report saved to {output}")
        except (ValueError, OSError) as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Individual sub-commands
# ---------------------------------------------------------------------------


@app.command("mx")
def cmd_mx(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Look up MX records for DOMAIN."""
    result = check_mx(domain)
    if as_json:
        _print_json(result)
    else:
        print_mx(result)


@app.command("smtp")
def cmd_smtp(
    host: Annotated[
        str,
        typer.Argument(
            help="Mail server hostname or IP address.", callback=_validate_host
        ),
    ],
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="SMTP port."),
    ] = 25,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Run SMTP diagnostics against HOST."""
    result = check_smtp(host, port=port)
    if as_json:
        _print_json(result)
    else:
        print_smtp([result])


@app.command("spf")
def cmd_spf(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Look up and validate the SPF record for DOMAIN."""
    result = check_spf(domain)
    if as_json:
        _print_json(result)
    else:
        print_spf(result)


@app.command("dmarc")
def cmd_dmarc(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Look up and validate the DMARC record for DOMAIN."""
    result = check_dmarc(domain)
    if as_json:
        _print_json(result)
    else:
        print_dmarc(result)


@app.command("dkim")
def cmd_dkim(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Check the DKIM base node (_domainkey.DOMAIN) for RFC 2308 conformance."""
    result = check_dkim(domain)
    if as_json:
        _print_json(result)
    else:
        print_dkim(result)


@app.command("bimi")
def cmd_bimi(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Look up and validate the BIMI record for DOMAIN."""
    result = check_bimi(domain)
    if as_json:
        _print_json(result)
    else:
        print_bimi(result)


@app.command("tlsrpt")
def cmd_tlsrpt(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Check the SMTP TLS Reporting (TLSRPT) record for DOMAIN."""
    result = check_tlsrpt(domain)
    if as_json:
        _print_json(result)
    else:
        print_tlsrpt(result)


@app.command("mta-sts")
def cmd_mta_sts(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Check the MTA-STS DNS record and policy file for DOMAIN."""
    result = check_mta_sts(domain)
    if as_json:
        _print_json(result)
    else:
        print_mta_sts(result)


@app.command("blacklist")
def cmd_blacklist(
    ip: Annotated[
        str,
        typer.Argument(help="IPv4 or IPv6 address to check.", callback=_validate_ip),
    ],
    workers: Annotated[
        int,
        typer.Option("--workers", "-w", help="Number of parallel DNS workers."),
    ] = 50,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Check IP against 100+ DNS blacklists."""
    result = check_blacklist(ip, max_workers=workers)
    if as_json:
        _print_json(result)
    else:
        print_blacklist(result)


@app.command("dnssec")
def cmd_dnssec(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output results as JSON."),
    ] = False,
) -> None:
    """Check DNSSEC chain-of-trust for DOMAIN and its MX server domain(s)."""
    domain_result = check_dnssec_domain(domain)
    mx_result = check_mx(domain)
    mx_dnssec = None
    if mx_result.records:
        mx_domains = [r.exchange for r in mx_result.records]
        mx_dnssec = check_dnssec_mx(mx_domains, email_domain=domain)

    if as_json:
        payload: dict = {"domain": dataclasses.asdict(domain_result)}
        if mx_dnssec is not None:
            payload["mx"] = dataclasses.asdict(mx_dnssec)
        typer.echo(json.dumps(payload, indent=2))
    else:
        print_dnssec_domain(domain_result)
        if mx_dnssec is not None:
            print_dnssec_mx(mx_dnssec)


if __name__ == "__main__":  # pragma: no cover
    app()
