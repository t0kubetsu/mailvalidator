# mailvalidator

> Assess the complete mail security posture of any domain — from the command
> line or as a Python library.

**mailvalidator** checks MX, DNSSEC, SPF, DMARC, DKIM, BIMI, TLSRPT, MTA-STS, SMTP
diagnostics, deep TLS inspection, and 104 DNS blacklists in a single command.
Results are colour-coded and graded against the
[NCSC-NL IT Security Guidelines for Transport Layer Security (TLS)](https://www.ncsc.nl/en/transport-layer-security-tls/security-guidelines-for-transport-layer-security-2025-05).

```
$ mailvalidator check example.com
```

![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![Tests](https://img.shields.io/badge/tests-608%20passing-brightgreen)
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

| Check                | Command                   | What is verified                                                                                                                                                                                                                                                                                                                            |
| -------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MX Records**       | `mailvalidator mx`        | Authoritative NS query, priority ordering, duplicate detection                                                                                                                                                                                                                                                                              |
| **DNSSEC**           | `mailvalidator dnssec`    | Chain-of-trust validation (Trust Anchor → `.` → TLD → domain) for the email address domain and each MX host domain; CNAME chain following; DANE prerequisite annotation (RFC 7671)                                                                                                                                                          |
| **SMTP Diagnostics** | `mailvalidator smtp`      | See [SMTP check details](#smtp-check-rfc-5321) below                                                                                                                                                                                                                                                                                        |
| **TLS Inspection**   | _(part of smtp)_          | TLS 1.0–1.3 version probing, 34 cipher suites graded per NCSC-NL, cipher order enforcement, key exchange (ECDHE/DHE/RSA), CRIME compression, RFC 5746 renegotiation, certificate trust chain/domain match/expiry                                                                                                                            |
| **SPF**              | `mailvalidator spf`       | Record lookup; `all`-qualifier grading; recursive `include:`/`redirect=` resolution with per-branch visited tracking; RFC 7208 §4.6.4 DNS lookup limit (10) and void lookup limit (2); `a/cidr` and `mx/cidr` mechanism counting; `include:` qualifier surfacing; nested `+all` detection; `exp=` modifier noted; `ptr` deprecation warning |
| **DMARC**            | `mailvalidator dmarc`     | Full RFC 7489 validation: policy grading, sp, pct range, adkim/aspf, fo, ri, rua/ruf scheme + mailto syntax + external destination verification (§7.1)                                                                                                                                                                                      |
| **DKIM**             | `mailvalidator dkim`      | Base-node (`_domainkey.<domain>`) RFC 2308 existence check                                                                                                                                                                                                                                                                                  |
| **BIMI**             | `mailvalidator bimi`      | Record lookup; multiple-record detection (exactly one required); logo URL (HTTPS + SVG/.svg.gz); empty `l=` VMC-only configuration; authority evidence `a=` (HTTPS, .pem/.crt format); unknown tag detection                                                                                                                                |
| **TLSRPT**           | `mailvalidator tlsrpt`    | RFC 8460: multiple-record detection; `v=` ordering (must be first tag); `rua=` required, at most two URIs, `mailto:` address syntax validation, `https://` scheme; unknown tag detection                                                                                                                                                    |
| **MTA-STS**          | `mailvalidator mta-sts`   | RFC 8461: multiple DNS record detection; `id=` format (1–32 alphanumeric); policy file `Content-Type: text/plain`; `version: STSv1` field; `mode` grading; `max_age` range (1 day – 1 year); `mx` hostname/wildcard pattern validation; CRLF line-ending conformance; `v=` tag ordering in DNS record                                       |
| **CAA**              | _(part of smtp)_          | RFC 8659: hierarchy walk; `issue` / `issuewild` tags checked independently; deny-all (`issue ";"`) surfaced; wildcard governance note when `issuewild` is absent; flags byte validation; `iodef` scheme validation (https:// or mailto: only)                                                                                               |
| **DANE / TLSA**      | _(part of smtp)_          | RFC 6698 / RFC 7671: TLSA existence; SHA-256/SHA-512 fingerprint match; rollover scheme; matching type 0 discouraged (RFC 7671 §5.1); DNSSEC prerequisite noted                                                                                                                                                                             |
| **Blacklist**        | `mailvalidator blacklist` | 104 DNSBL zones in parallel, RFC 5782 §2.1 compliant                                                                                                                                                                                                                                                                                        |
| **Full Report**      | `mailvalidator check`     | All of the above in one command, plus a **Security Verdict** panel with prioritised action items |

### SMTP check (RFC 5321)

The SMTP check targets **external-facing MX servers** that accept inbound mail
on **port 25** (RFC 5321 §2.1, §4.5.3.2). Port 587 is the _submission_ port
(RFC 6409) and requires AUTH — it is a different service and these checks are
not meaningful against it.

Results are grouped into four colour-coded panels: **Protocol** (connection,
banner, EHLO, extensions, STARTTLS, VRFY, open relay), **TLS** (version
probing, ciphers, key exchange, compression, renegotiation), **Certificate**
(trust chain, public key, SAN/domain match, expiry), and **DNS** (PTR, CAA,
DANE/TLSA).

| Sub-check                | RFC reference                          | What is verified                                                                         |
| ------------------------ | -------------------------------------- | ---------------------------------------------------------------------------------------- |
| **Connect / latency**    | RFC 5321 §3.1                          | TCP connect time and 220 banner                                                          |
| **Banner FQDN**          | RFC 5321 §4.1.3                        | 220 greeting MUST include the server's fully-qualified domain name; bare IPs are flagged |
| **Reverse DNS (PTR)**    | Best practice                          | Server IP must have a PTR record; many receivers reject mail without one                 |
| **EHLO domain**          | RFC 5321 §4.1.1.1                      | EHLO 250 response MUST name the server as a valid FQDN; IP domain literals are flagged   |
| **ESMTP extensions**     | RFC 1870, RFC 2920, RFC 6152, RFC 6531 | Presence of SIZE, PIPELINING, 8BITMIME, SMTPUTF8                                         |
| **STARTTLS**             | RFC 3207                               | STARTTLS advertisement                                                                   |
| **VRFY command**         | RFC 5321 §3.5.3                        | 252 = privacy-preserving (recommended); 502 = disabled (acceptable); other codes noted   |
| **Open relay**           | RFC 5321 §3.9                          | Server must reject relaying for unrelated external addresses                             |
| **TLS versions**         | NCSC-NL TLS guidelines                 | TLS 1.3 OK · TLS 1.2 Sufficient · TLS 1.1/1.0 Phase-out                                  |
| **Cipher suites**        | NCSC-NL TLS guidelines                 | 34 suites graded Good / Sufficient / Phase-out / Insufficient                            |
| **Cipher order**         | NCSC-NL TLS guidelines                 | Server-preference enforcement and Good→Sufficient→Phase-out ordering                     |
| **Key exchange**         | NCSC-NL TLS guidelines                 | ECDHE curve and DHE group strength                                                       |
| **TLS compression**      | CVE-2012-4929                          | Deflate/zlib compression enables the CRIME attack                                        |
| **Secure renegotiation** | RFC 5746                               | Renegotiation Info extension                                                             |
| **Certificate**          | RFC 5280, RFC 6125                     | Trust chain, public key strength, signature algorithm, SAN/CN domain match, expiry       |
| **CAA records**          | RFC 8659                               | Issue/issuewild/iodef tags; flags byte; hierarchy walk                                   |
| **DANE / TLSA**          | RFC 6698, RFC 7671                     | TLSA existence, fingerprint verification, rollover scheme                                |

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

**From source (recommended):**

```bash
git clone --recurse-submodules https://github.com/t0kubetsu/mailvalidator.git
cd mailvalidator
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"   # installs the CLI + all dev/test dependencies
```

The `mailvalidator` command is then available in your shell.

> **Note:** `--recurse-submodules` is required — `vendor/chainvalidator` is a
> git submodule and will be missing without it.

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

104 DNS blacklist zones are queried in parallel using a
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
│       ├── smtp/          SMTP diagnostics + deep TLS inspection (RFC 5321)
│       │   ├── __init__.py    Re-exports public API (check_smtp)
│       │   ├── _check.py      Orchestrator — runs all sub-checks, tags sections
│       │   ├── _classify.py   TLS version / cipher / curve classification
│       │   ├── _connection.py TCP connect helper
│       │   ├── _cert.py       Certificate validation checks
│       │   ├── _tls_probe.py  STARTTLS handshake + cipher enumeration
│       │   ├── _tls_checks.py TLS version, cipher, key-exchange, compression, renegotiation
│       │   ├── _dns.py        CAA and DANE/TLSA checks
│       │   └── _protocol.py   Banner FQDN, EHLO, ESMTP extensions, VRFY, open relay
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

# Run all tests with coverage (configured automatically via pyproject.toml)
pytest

# Run a single module
pytest tests/checks/test_smtp.py -v

# Run a single test class
pytest tests/checks/test_spf.py::TestSPFCoverage -v
```

The test suite has **608 tests** and achieves **100% coverage** (1 820
statements) across all modules. Coverage reporting is pre-configured in
`pyproject.toml` — no extra flags needed.

SMTP network I/O functions (`_probe_tls`, `check_smtp`, etc.) require a live
mail server and are excluded from unit tests via `# pragma: no cover`;
integration tests against a real server are out of scope for the unit suite.
DNSSEC checks call chainvalidator's `assess()` with all DNS I/O mocked at
the boundary — no real nameserver is contacted during the test run. File
export is tested by mocking Rich's `console.save_text`, `save_svg`, and
`save_html` methods.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Add or update tests — the project targets 100% unit test coverage.
3. Run `pytest` and confirm all 608 tests pass before opening a pull request.
4. Follow the existing docstring format (reStructuredText / docutils field lists).
5. Use [conventional commits](https://www.conventionalcommits.org/):
   `fix:`, `feat:`, `refactor:`, `test:`, `docs:`, `chore:`

---

## License

GPLv3 — see [LICENSE](LICENSE) for details.
