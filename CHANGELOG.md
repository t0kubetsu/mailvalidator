# Changelog

All notable changes to **mailvalidator** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.5] — 2026-04-29

### Added
- **SMTP port fallback** — when port 25 is refused, times out, or drops the
  connection after the TCP handshake (banner-read timeout), the tool now
  automatically retries on port **587** (RFC 6409 Mail Submission) and then
  port **465** (RFC 8314 Implicit-TLS SMTP) before reporting failure.
- New `SMTP Port Fallback` (`INFO`) check result records which fallback port
  was actually used, visible in both the terminal report and `--json` output.

### Fixed
- `smtplib.SMTPServerDisconnected` exceptions (e.g. "Connection unexpectedly
  closed: timed out") now correctly trigger the port fallback instead of
  failing immediately without retrying.

### Changed
- `check_smtp` docstring updated to document the automatic port-retry
  behaviour.
- `SMTP Connect` CRITICAL entry in `docs/SECURITY_VERDICT.md` updated to
  describe the three-port probe sequence; new `SMTP Port Fallback` INFO entry
  added.
- `README.md` SMTP check section updated to describe the port fallback.

### Tests
- `TestConnectOrFallback` — 8 new unit tests covering all fallback branches:
  primary success, fallback to 587, fallback to 465, all-ports-fail,
  non-refusal `OSError` (no retry), `TimeoutError`, `SMTPServerDisconnected`,
  and empty-fallback-tuple guard.

---

## [0.1.4] — 2025

### Added
- `--json` flag on all CLI sub-commands (`check`, `smtp`, `spf`, `dmarc`,
  `dkim`, `bimi`, `tlsrpt`, `mta-sts`, `blacklist`, `dnssec`) — prints the
  full result as machine-readable JSON to stdout.

### Fixed
- Verdict panel no longer emits cipher-suite or cipher-order action items for
  deprecated TLS versions (TLS 1.0/1.1); those issues are already covered by
  the TLS-version action.

### Changed
- Repository moved to the
  [NC3-TestingPlatform](https://github.com/NC3-TestingPlatform) GitHub
  organisation; all internal URLs updated.
- `vendor/chainvalidator` declared as a local path dependency in
  `pyproject.toml`.

---

## [0.1.3] — 2025

### Added
- `docs/SECURITY_VERDICT.md` — CISO-facing reference explaining the
  penalty-point grading model and the rationale for each check's severity.

### Changed
- Terminal reporter: check tables wrapped in Rich panels with `ROUNDED` style;
  inner SMTP section panels use `bright_white`/`white` colour scheme for
  readability.
- Security Verdict panel aligned with headersvalidator style (consistent
  cross-tool look).

---

## [0.1.0] — 2024

### Added
- Initial release of **mailvalidator**.
- Checks: MX records, SPF, DMARC, DKIM base node, BIMI, TLSRPT, MTA-STS,
  SMTP diagnostics (Protocol, TLS, Certificate, DNS sections), 104 DNSBL
  blacklist zones, DNSSEC chain-of-trust.
- Deep TLS inspection: TLS 1.0–1.3 version probing, 34 cipher suites graded
  per NCSC-NL guidelines, cipher order enforcement, ECDHE/DHE/RSA key
  exchange, CRIME compression, RFC 5746 renegotiation.
- DNS checks per MX server: reverse PTR, CAA, DANE/TLSA.
- CLI entry points: `mailvalidator check`, `mailvalidator smtp`,
  `mailvalidator spf`, `mailvalidator dmarc`, `mailvalidator dkim`,
  `mailvalidator bimi`, `mailvalidator tlsrpt`, `mailvalidator mta-sts`,
  `mailvalidator blacklist`, `mailvalidator dnssec`.
- `--output` flag for `.txt` / `.svg` / `.html` report export.
- 685 unit tests, 100% coverage.

---

[Unreleased]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.0...v0.1.3
[0.1.0]: https://github.com/NC3-TestingPlatform/mailvalidator/releases/tag/v0.1.0
