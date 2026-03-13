# mailcheck

> Mail server configuration assessment CLI utility and Python module.

## Features

| Check | Command | Description |
|---|---|---|
| MX Records | `mailcheck mx` | Lists MX records via authoritative NS |
| SMTP Diagnostics | `mailcheck smtp` | Banner, PTR, open relay test, STARTTLS, response time |
| SPF | `mailcheck spf` | SPF record lookup + validation |
| DMARC | `mailcheck dmarc` | DMARC record lookup + policy validation |
| DKIM | `mailcheck dkim` | DKIM record lookup + key validation |
| BIMI | `mailcheck bimi` | BIMI record lookup + logo/VMC checks |
| TLSRPT | `mailcheck tlsrpt` | SMTP TLS Reporting record check |
| MTA-STS | `mailcheck mta-sts` | MTA-STS DNS record + policy file validation |
| Blacklist / Blocklist | `mailcheck blacklist` | Check IP against 100+ DNSBLs |
| **Full Report** | `mailcheck check` | Runs all checks in one go |

## Requirements

- Python ≥ 3.11
- `dnspython`, `rich`, `typer`, `aiohttp`

## Installation

```bash
pip install -e .
```

## CLI Usage

```bash
# Full report
mailcheck check example.com

# Full report – skip SMTP & blacklist (faster, no outbound TCP 25)
mailcheck check example.com --no-smtp --no-blacklist

# Individual checks
mailcheck mx      example.com
mailcheck smtp    mail.example.com --port 25
mailcheck spf     example.com
mailcheck dmarc   example.com
mailcheck dkim    example.com --selector google
mailcheck bimi    example.com
mailcheck tlsrpt  example.com
mailcheck mta-sts example.com
mailcheck blacklist 1.2.3.4
```

## Python API

```python
from assessor import assess
from reporter import print_full_report

report = assess("example.com", run_smtp=False, run_blacklist=False)
print_full_report(report)

# Individual checks
from checks.spf import check_spf
from checks.dmarc import check_dmarc

spf = check_spf("example.com")
dmarc = check_dmarc("example.com")
```

## Project Structure

```
mailcheck/
├── mailcheck/
│   ├── __init__.py
│   ├── models.py        # Dataclass result models
│   ├── dns_utils.py     # DNS helper functions
│   ├── assessor.py      # Orchestration / public API
│   ├── reporter.py      # Rich terminal output
│   ├── cli.py           # Typer CLI entry point
│   └── checks/
│       ├── mx.py
│       ├── smtp.py
│       ├── spf.py
│       ├── dmarc.py
│       ├── dkim.py
│       ├── bimi.py
│       ├── tlsrpt.py
│       ├── mta_sts.py
│       └── blacklist.py
└── pyproject.toml
```
