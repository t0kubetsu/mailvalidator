# mailvalidator – Project Instructions

## Overview

Mail server configuration assessment CLI tool. Validates MX, SPF, DKIM, DMARC, BIMI,
MTA-STS, TLSRPT, DNSSEC, SMTP diagnostics, and DNS blacklists for a given domain.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python ≥ 3.11 |
| CLI framework | Typer |
| Console output | Rich |
| DNS resolution | dnspython |
| HTTP (MTA-STS) | aiohttp |
| Crypto (TLS) | cryptography |
| Testing | pytest + pytest-cov |
| Vendored dep | `vendor/chainvalidator` (git submodule) |

## Project Structure

```
mailvalidator/
├── cli.py         → Typer CLI entry point; all sub-commands defined here
├── assessor.py    → assess() orchestrates the full check pipeline
├── models.py      → All dataclasses (CheckResult, Status, *Result, FullReport)
├── dns_utils.py   → Shared DNS helpers
├── reporter.py    → Rich rendering for each result type + save_report()
├── verdict.py     → Security verdict extraction: severity mapping, action deduplication
└── checks/        → One module per check: spf, dmarc, dkim, bimi, mx,
   │                  mta_sts, tlsrpt, blacklist, dnssec
   └── smtp/        → SMTP diagnostics package (split from smtp.py)
       ├── __init__.py   → Re-exports public API; patch target namespace
       ├── _check.py     → check_smtp() entry point; orchestrates all sub-checks
       ├── _classify.py  → TLS version/cipher/curve classification helpers
       ├── _connection.py→ TCP + TLS connection helpers
       ├── _cert.py      → Certificate validation checks
       ├── _tls_probe.py → TLS version/cipher probing via raw ssl connections
       ├── _tls_checks.py→ TLS version, cipher, key-exchange, compression, renegotiation checks
       ├── _dns.py       → CAA and DANE/TLSA checks
       └── _protocol.py  → Banner FQDN, EHLO domain, ESMTP extensions, VRFY, open relay
tests/
├── conftest.py    → Shared factories (make_tls, make_mx_result, console_capture…)
└── checks/        → One test file per checks/ module
vendor/chainvalidator/  → Git submodule; installed via requirements.txt
```

## Data Model Pattern

Every check function follows this contract:

```python
def check_<name>(domain: str) -> <Name>Result:
    result = <Name>Result(domain=domain)
    result.checks.append(CheckResult(name="...", status=Status.OK, value="..."))
    return result
```

- `Status` enum: `OK`, `GOOD`, `SUFFICIENT`, `INFO`, `NA`, `WARNING`, `PHASE_OUT`,
  `INSUFFICIENT`, `ERROR`, `NOT_FOUND`
- All models are plain `@dataclass` with Sphinx-style docstrings
- `FullReport` aggregates all `*Result` objects

## Build & Run

```bash
# Install in editable mode (include vendored dep)
pip install -e ".[dev]"

# Run the CLI
mailvalidator check example.com
mailvalidator spf example.com
mailvalidator smtp mx1.example.com --port 587
mailvalidator blacklist 203.0.113.42

# Run all tests with coverage
pytest

# Run a specific test file
pytest tests/checks/test_spf.py -v
```

## Testing

- Test runner: `pytest` (auto-configured via `pyproject.toml`)
- Coverage flag already wired: `--cov=mailvalidator --cov-report=term-missing`
- **Current state: 697 tests, 100% coverage** across all 19 modules (2 010 statements)
- Shared fixtures in `tests/conftest.py` — use `make_tls()`, `make_mx_result()`,
  `console_capture()`, `make_simple_result()`, `make_rsa_cert_der()`,
  `make_ec_cert_der()` rather than building objects by hand
- Test files mirror the source: `mailvalidator/checks/spf.py` → `tests/checks/test_spf.py`
- Mock DNS calls and network I/O at the boundary (`unittest.mock.patch`)
- Private helpers (e.g. `_check_caa`, `_check_dane`) are imported directly in tests
  to cover branches not reachable through the public `check_smtp()` API

## Conventions

- `from __future__ import annotations` at top of every module
- Snake_case for all files, functions, variables
- Sphinx-style docstrings: `:param name:`, `:returns:`, `:rtype:`
- Conventional commits: `fix:`, `feat:`, `fix(scope):`, `refactor:`, `test:`, `docs:`
- Input validation lives in `cli.py` (`_validate_domain`, `_validate_host`, `_validate_ip`)
- `resolve()` from `dns_utils` is the single DNS abstraction; patch it in tests
- No CI config currently present

## Before Every Commit

Run these checks and update these files as needed — do not skip any step:

```bash
# 1. Verify tests pass and coverage is still 100%
pytest
```

If the test count or statement count changed, update **all two** occurrences in `README.md`:
- Line ~17: badge `![Tests](https://img.shields.io/badge/tests-NNN%20passing-brightgreen)`
- "The test suite has **NNN tests**…" paragraph (Running Tests section)

Also update the count in this file (`CLAUDE.md`) under "Current state".

```bash
# 2. Check for lint issues
ruff check mailvalidator/
```

Fix any F401 (unused import) or other errors before committing.

Before pushing, update **CHANGELOG.md**: add your changes under `## [Unreleased]`
using the standard sections (`### Added`, `### Changed`, `### Fixed`, `### Removed`).
When bumping the version, move unreleased items to a new `## [x.y.z] — YYYY-MM-DD`
section and update the comparison links at the bottom of `CHANGELOG.md`.

## Version Bumping

When committing a set of changes, bump the version using semver:
- **patch** (`0.1.x`) — bug fixes, RFC compliance fixes, lint/refactor, docs
- **minor** (`0.x.0`) — new checks, new CLI commands, new features
- **major** (`x.0.0`) — breaking API changes

Two files must always be updated together:
- `pyproject.toml` → `version = "x.y.z"`
- `mailvalidator/__init__.py` → fallback `__version__ = "x.y.z"` (the `except` branch)

## Where to Look

| I want to… | Look at… |
|------------|---------|
| Add a new check | `mailvalidator/checks/` + `models.py` + `reporter.py` + wire into `assessor.py` and `cli.py` |
| Change result rendering | `mailvalidator/reporter.py` |
| Add a CLI flag | `mailvalidator/cli.py` |
| Change the data model | `mailvalidator/models.py` |
| Add DNS utilities | `mailvalidator/dns_utils.py` |
| Add/fix tests | `tests/checks/test_<name>.py` + `tests/conftest.py` for fixtures |
| Change severity of a check | `mailvalidator/verdict.py` (`_PRIORITY` dict) + update `docs/SECURITY_VERDICT.md` |
| Explain grading to a CISO | `docs/SECURITY_VERDICT.md` |
