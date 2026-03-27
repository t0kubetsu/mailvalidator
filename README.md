# mailvalidator

> Assess the complete mail security posture of any domain — from the command
> line or as a Python library.

**mailvalidator** checks MX, SPF, DMARC, DKIM, BIMI, TLSRPT, MTA-STS, SMTP
diagnostics, deep TLS inspection, and 104 DNS blacklists in a single command.
Results are colour-coded and graded against the
[NCSC-NL IT Security Guidelines for Transport Layer Security (TLS)](https://www.ncsc.nl/en/transport-layer-security-tls/security-guidelines-for-transport-layer-security-2025-05).

```
$ mailvalidator check example.com
```

![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![Tests](https://img.shields.io/badge/tests-353%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![License](https://img.shields.io/badge/license-GPLv3-lightgrey)

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Python API](#python-api)
- [TLS Grading](#tls-grading)
- [DNSBL Blacklist Check](#dnsbl-blacklist-check)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Contributing](#contributing)

---

## Features

| Check                | Command                   | What is verified                                                                                                                                                                                                 |
| -------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MX Records**       | `mailvalidator mx`        | Authoritative NS query, priority ordering, duplicate detection                                                                                                                                                   |
| **DNSSEC**           | `mailvalidator dnssec`    | Chain-of-trust validation (Trust Anchor → `.` → TLD → domain) for the email address domain and each MX host domain; CNAME chain following; DANE prerequisite annotation (RFC 7671)                               |
| **SMTP Diagnostics** | `mailvalidator smtp`      | TCP connect latency, banner, PTR record, open relay, STARTTLS                                                                                                                                                    |
| **TLS Inspection**   | _(part of smtp)_          | TLS 1.0–1.3 version probing, 34 cipher suites graded per NCSC-NL, cipher order enforcement, key exchange (ECDHE/DHE/RSA), CRIME compression, RFC 5746 renegotiation, certificate trust chain/domain match/expiry |
| **SPF**              | `mailvalidator spf`       | Record lookup, all-qualifier grading, recursive include/redirect resolution, RFC 7208 lookup-count limit                                                                                                         |
| **DMARC**            | `mailvalidator dmarc`     | Policy grading (none/quarantine/reject), pct, sp, rua, ruf, adkim/aspf alignment                                                                                                                                 |
| **DKIM**             | `mailvalidator dkim`      | Base-node (`_domainkey.<domain>`) RFC 2308 existence check                                                                                                                                                       |
| **BIMI**             | `mailvalidator bimi`      | Record lookup, logo URL (HTTPS + SVG), VMC authority evidence                                                                                                                                                    |
| **TLSRPT**           | `mailvalidator tlsrpt`    | RFC 8460 record lookup, rua scheme validation (mailto/HTTPS)                                                                                                                                                     |
| **MTA-STS**          | `mailvalidator mta-sts`   | DNS record + HTTPS policy file fetch, mode, max_age, MX entries                                                                                                                                                  |
| **CAA**              | _(part of smtp)_          | RFC 8659 hierarchy walk, issue/issuewild tags, iodef HTTPS enforcement                                                                                                                                           |
| **DANE / TLSA**      | _(part of smtp)_          | TLSA existence, SHA-256/SHA-512 fingerprint match, rollover scheme                                                                                                                                               |
| **Blacklist**        | `mailvalidator blacklist` | 101 DNSBL zones in parallel, RFC 5782 §2.1 compliant                                                                                                                                                             |
| **Full Report**      | `mailvalidator check`     | All of the above in one command                                                                                                                                                                                  |

---

## Requirements

- Python ≥ 3.11
- [`dnspython`](https://www.dnspython.org/) ≥ 2.6
- [`rich`](https://github.com/Textualize/rich) ≥ 13.7
- [`typer`](https://typer.tiangolo.com/) ≥ 0.12
- [`cryptography`](https://cryptography.io/) ≥ 42
- [`chainvalidator`](https://github.com/t0kubetsu/chainvalidator) (local dependency — see installation)

---

## Installation

**From source:**

```bash
git clone --recurse-submodules https://github.com/t0kubetsu/mailvalidator.git
cd mailvalidator
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**As an editable package:**

```bash
pip install -e .
```

The `mailvalidator` command is then available in your shell.

---

## CLI Usage

### Full report

```bash
# All checks — MX, SMTP/TLS, SPF, DMARC, DKIM, BIMI, TLSRPT, MTA-STS, blacklist
mailvalidator check example.com

# Skip SMTP and blacklist (faster, no outbound TCP port 25 needed)
mailvalidator check example.com --no-smtp --no-blacklist

# Skip DNSSEC chain-of-trust validation
mailvalidator check example.com --no-dnssec

# Non-standard SMTP port
mailvalidator check example.com --smtp-port 587

# Export the report to a file (.txt, .svg, or .html)
mailvalidator check example.com --output report.txt
mailvalidator check example.com --output report.svg
mailvalidator check example.com --output report.html
```

### Individual checks

```bash
mailvalidator mx        example.com
mailvalidator dnssec    example.com
mailvalidator spf       example.com
mailvalidator dmarc     example.com
mailvalidator dkim      example.com
mailvalidator bimi      example.com
mailvalidator tlsrpt    example.com
mailvalidator mta-sts   example.com

# SMTP + full TLS inspection against a specific host
mailvalidator smtp mail.example.com
mailvalidator smtp mail.example.com --port 587

# Blacklist check
mailvalidator blacklist 203.0.113.42
mailvalidator blacklist 203.0.113.42 --workers 100
```

### Version

```bash
mailvalidator --version
```

---

## Python API

### Full assessment

```python
from mailvalidator.assessor import assess
from mailvalidator.reporter import print_full_report

report = assess(
    "example.com",
    smtp_port=25,
    run_smtp=True,
    run_blacklist=True,
    run_dnssec=True,
    progress_cb=print,   # optional: called with a status string before each step
)

print_full_report(report)
```

### Individual checks

```python
from mailvalidator.checks.spf       import check_spf
from mailvalidator.checks.dmarc     import check_dmarc
from mailvalidator.checks.dkim      import check_dkim
from mailvalidator.checks.bimi      import check_bimi
from mailvalidator.checks.tlsrpt    import check_tlsrpt
from mailvalidator.checks.mta_sts   import check_mta_sts
from mailvalidator.checks.mx        import check_mx
from mailvalidator.checks.blacklist import check_blacklist
from mailvalidator.checks.smtp      import check_smtp
from mailvalidator.checks.dnssec    import check_dnssec_domain, check_dnssec_mx

spf    = check_spf("example.com")
dmarc  = check_dmarc("example.com")
mx     = check_mx("example.com")
dnssec = check_dnssec_domain("example.com")
mx_sec = check_dnssec_mx([r.exchange for r in mx.records], email_domain="example.com")
smtp   = check_smtp("mail.example.com", port=25)
bl     = check_blacklist("203.0.113.42")
```

### Working with results

Every check function returns a result dataclass with a `checks` list of
`CheckResult` objects:

```python
result = check_spf("example.com")

for check in result.checks:
    print(check.name, check.status.value, check.value)
    for detail in check.details:
        print("  ", detail)
```

`Status` values: `OK`, `WARNING`, `ERROR`, `INFO`, `NOT_FOUND`,
`GOOD`, `SUFFICIENT`, `PHASE_OUT`, `INSUFFICIENT`, `NA`.

---

## TLS Grading

TLS checks follow the
[NCSC-NL IT Security Guidelines for Transport Layer Security (TLS)](https://www.ncsc.nl/en/transport-layer-security-tls/security-guidelines-for-transport-layer-security-2025-05).

| Grade            | Criteria                                         | Examples                                               |
| ---------------- | ------------------------------------------------ | ------------------------------------------------------ |
| **Good**         | Forward-secret AEAD cipher + strong key exchange | All TLS 1.3 suites, `ECDHE-RSA-AES256-GCM-SHA384`      |
| **Sufficient**   | Forward-secret but CBC mode or DHE overhead      | `ECDHE-RSA-AES256-SHA384`, `DHE-RSA-AES256-GCM-SHA384` |
| **Phase-out**    | No forward secrecy or weak block cipher          | RSA key exchange ciphers, 3DES (Sweet32)               |
| **Insufficient** | Broken or unsafe                                 | NULL, anonymous, export, RC4                           |

**TLS versions:** TLS 1.3 → OK · TLS 1.2 → Sufficient · TLS 1.1/1.0 → Phase-out.

Beyond cipher grading, the SMTP check also verifies:

- Server cipher-preference enforcement per version
- Prescribed cipher ordering (Good → Sufficient → Phase-out)
- EC curve and DH group strength (key exchange)
- Key-exchange hash function (SHA-1/MD5 flagged)
- TLS-layer compression (CRIME, CVE-2012-4929)
- Secure renegotiation (RFC 5746)
- Certificate trust chain, public key strength, signature algorithm, domain match, and expiry
- CAA records (RFC 8659)
- DANE/TLSA records with fingerprint verification and rollover scheme assessment

---

## DNSBL Blacklist Check

101 DNS blacklist zones are queried in parallel using a
`ThreadPoolExecutor`. A positive listing is confirmed only when the DNS
response is exactly `127.0.0.2` (RFC 5782 §2.1 standard "listed" response).

Other `127.0.0.x` return codes used by reputation or allowlist zones — for
example `127.255.255.255` from `query.bondedsender.org` — are intentionally
ignored to prevent false positives for IPs that are not actually blacklisted.

---

## Project Structure

```
mailvalidator/
├── mailvalidator/
│   ├── __init__.py        Package version
│   ├── models.py          Dataclass result models + Status enum
│   ├── dns_utils.py       DNS resolver helpers
│   ├── assessor.py        High-level API — orchestrates all checks
│   ├── reporter.py        Rich terminal output
│   ├── cli.py             Typer CLI entry point
│   └── checks/
│       ├── mx.py
│       ├── dnssec.py      DNSSEC chain-of-trust checks (requires chainvalidator)
│       ├── smtp.py        SMTP diagnostics + deep TLS inspection
│       ├── spf.py
│       ├── dmarc.py
│       ├── dkim.py
│       ├── bimi.py
│       ├── tlsrpt.py
│       ├── mta_sts.py
│       └── blacklist.py   104 DNSBL zones
├── tests/
│   ├── conftest.py        Shared fixtures and factories
│   ├── test_init.py
│   ├── test_dns_utils.py
│   ├── test_assessor.py
│   ├── test_reporter.py
│   ├── test_cli.py
│   └── checks/
│       ├── test_mx.py
│       ├── test_dnssec.py
│       ├── test_smtp.py
│       ├── test_spf.py
│       ├── test_dmarc.py
│       ├── test_dkim.py
│       ├── test_bimi.py
│       ├── test_tlsrpt.py
│       ├── test_mta_sts.py
│       └── test_blacklist.py
├── requirements.txt
└── pyproject.toml
```

---

## Running Tests

```bash
source .venv/bin/activate

# Run all tests
pytest tests/

# Run a single module
pytest tests/checks/test_smtp.py

# Run a single test class
pytest tests/checks/test_spf.py::TestSPFCoverage -v
```

The test suite has **353 tests** and achieves **100% coverage** of all
testable code. SMTP network I/O functions (`_probe_tls`, `check_smtp`, etc.)
require a live mail server and are excluded from unit tests via
`# pragma: no cover`; integration tests against a real server are out of
scope for the unit suite. DNSSEC checks call chainvalidator's `assess()`
with all DNS I/O mocked at the boundary — no real nameserver is contacted
during the test run. File export is tested by mocking Rich's
`console.save_text`, `save_svg`, and `save_html` methods.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Add or update tests — the project targets 100% unit test coverage.
3. Run `pytest tests/` and confirm all tests pass before opening a pull request.
4. Follow the existing docstring format (reStructuredText / docutils field lists).

---

## License

GPLv3 — see [LICENSE](LICENSE) for details.
