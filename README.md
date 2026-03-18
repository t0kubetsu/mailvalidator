# mailvalidator

> Mail server configuration assessment CLI utility and Python module.

## Features

| Check | Command | Description |
|---|---|---|
| MX Records | `mailvalidator mx` | Lists MX records via authoritative NS |
| SMTP Diagnostics | `mailvalidator smtp` | Banner, PTR, open relay test, STARTTLS, response time |
| SPF | `mailvalidator spf` | SPF record lookup + validation |
| DMARC | `mailvalidator dmarc` | DMARC record lookup + policy validation |
| DKIM | `mailvalidator dkim` | DKIM record lookup + key validation |
| BIMI | `mailvalidator bimi` | BIMI record lookup + logo/VMC checks |
| TLSRPT | `mailvalidator tlsrpt` | SMTP TLS Reporting record check |
| MTA-STS | `mailvalidator mta-sts` | MTA-STS DNS record + policy file validation |
| Blacklist / Blocklist | `mailvalidator blacklist` | Check IP against 100+ DNSBLs |
| **Full Report** | `mailvalidator check` | Runs all checks in one go |

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
mailvalidator check example.com

# Full report – skip SMTP & blacklist (faster, no outbound TCP 25)
mailvalidator check example.com --no-smtp --no-blacklist

# Individual checks
mailvalidator mx      example.com
mailvalidator smtp    mail.example.com --port 25
mailvalidator spf     example.com
mailvalidator dmarc   example.com
mailvalidator dkim    example.com --selector google
mailvalidator bimi    example.com
mailvalidator tlsrpt  example.com
mailvalidator mta-sts example.com
mailvalidator blacklist 1.2.3.4
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
mailvalidator/
├── mailvalidator/
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
