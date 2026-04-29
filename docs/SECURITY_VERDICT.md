# Security Verdict & Grading Reference

This document explains how **mailvalidator** grades a mail server configuration
and why each check carries its assigned severity.  It is intended for security
teams and CISOs who need to understand the risk rationale behind each finding.

---

## Grading Model

Every `mailvalidator check` run produces a **Security Verdict** panel with
prioritised action items and a letter grade.  The grading uses a
**penalty-point** model: a perfect configuration starts at **0 points** (A+)
and accumulates points as issues are found.

### Penalty weights

| Severity     | Penalty per finding |
| ------------ | ------------------- |
| **CRITICAL** | 25 pts              |
| **HIGH**     | 10 pts              |
| **MEDIUM**   | 3 pts               |

### Grade thresholds

| Penalty points | Grade  | Interpretation                                          |
| -------------- | ------ | ------------------------------------------------------- |
| 0              | **A+** | Perfect — no issues found                               |
| 1 – 10         | **A**  | Excellent — only minor gaps                             |
| 11 – 20        | **B**  | Good — some improvements needed                         |
| 21 – 30        | **C**  | Fair — multiple gaps; prioritise CRITICAL/HIGH items    |
| 31 – 40        | **D**  | Poor — significant risks; immediate action recommended  |
| > 40           | **F**  | Failing — foundational controls missing                 |

---

## CRITICAL — 25 pts each

A single CRITICAL finding drops the grade from A+ to at most A (25 pts), and
two CRITICAL findings push the domain to grade C (50 pts).  These checks cover
foundational controls whose absence or failure directly exposes the organisation
to active attack or immediate deliverability loss.

### SPF Record

**What it checks:** A valid `TXT` record beginning with `v=spf1` exists at the
domain's DNS zone.

**Why CRITICAL:**  
SPF (RFC 7208) tells receiving mail servers which hosts are authorised to send
email on behalf of the domain.  Without an SPF record any attacker can send
email that claims to be from your domain and pass basic origin checks.  Most
spam filters and large mailbox providers (Google, Microsoft) will either reject
or heavily penalise mail from domains with no SPF record, causing deliverability
failures in addition to the spoofing risk.

**Remediation:** Publish a `v=spf1 … -all` record listing all authorised
sending infrastructure.  Use `-all` (hard fail) or `~all` (soft fail);
never use `+all`.

---

### DMARC Record

**What it checks:** A valid `TXT` record exists at `_dmarc.<domain>` with at
minimum a `v=DMARC1; p=` policy.

**Why CRITICAL:**  
DMARC (RFC 7489) is the mechanism that binds SPF and DKIM together and instructs
receivers what to do when alignment fails — i.e. when a message claims to be
from your domain but does not pass authentication.  Without DMARC, even a
correctly configured SPF record provides no protection against domain spoofing
because the envelope `From` and the header `From` can differ.  A missing DMARC
record also disqualifies the domain from Google and Yahoo bulk-sender
requirements (effective 2024), causing deliverability failures at scale.

**Related:** A DMARC record with `p=none` is reported as HIGH (not CRITICAL)
because the record exists and reporting is active, but enforcement is absent.

**Remediation:** Start with `p=quarantine` and move to `p=reject` once
reporting confirms no legitimate traffic is failing authentication.

---

### MX Records

**What it checks:** At least one valid MX record is resolvable at the domain.

**Why CRITICAL:**  
Without MX records, the domain cannot receive email.  An invalid or missing MX
configuration means all inbound mail is bounced or silently discarded.  This is
a foundational operational requirement (RFC 5321 §5).

**Remediation:** Ensure MX records are published and point to reachable,
correctly configured mail servers.

---

### Open Relay

**What it checks:** The SMTP server accepts relay attempts for unrelated
external addresses (e.g. sends mail destined for a domain it does not host
without requiring authentication).

**Why CRITICAL:**  
An open relay is one of the most severe SMTP misconfigurations (RFC 5321 §3.9).
Spammers actively scan for and exploit open relays to send bulk unsolicited
email using your server's resources and IP reputation.  The IP will be
blacklisted within hours of discovery, rendering all outbound mail from the
domain undeliverable.

**Remediation:** Configure your MTA to relay only for authenticated users or
for domains it is authorised to handle.  Restrict relay rules to explicitly
listed domains/subnets.

---

### Certificate Trust Chain

**What it checks:** The TLS certificate presented on port 25 (STARTTLS) chains
to a publicly trusted root CA without errors.

**Why CRITICAL:**  
Mail servers that present an untrusted certificate prevent opportunistic TLS
from being established by security-conscious senders.  More critically, MTA-STS
(when enforced) will cause delivering servers to refuse the connection
entirely, resulting in non-delivery of email.  An untrusted certificate is also
a strong indicator of misconfiguration or a potential interception attack.

**Remediation:** Replace the certificate with one signed by a publicly trusted
CA (e.g. Let's Encrypt, DigiCert).  Ensure the full intermediate chain is
served.

---

### Certificate Expiry

**What it checks:** The TLS certificate presented has not expired and will not
expire within 14 days.

**Why CRITICAL:**  
An expired certificate causes the same deliverability consequences as an
untrusted chain — MTA-STS-enforcing senders will refuse the connection.
Certificate expiry is operationally avoidable and indicates a gap in renewal
monitoring.

**Remediation:** Automate certificate renewal (e.g. via ACME/Let's Encrypt) and
monitor expiry dates with at least 30 days' advance notice.

---

### Blacklist Status

**What it checks:** The MX server's IP address is checked against 104 DNSBL
zones.

**Why CRITICAL:**  
An IP listed on a major DNSBL will have its outbound mail rejected or filtered
by most receiving mail servers.  Blacklisting typically follows from spam
activity, open relay exploitation, or compromised accounts.  The impact is
immediate and organisation-wide — all email sent from that IP is affected.

**Remediation:** Identify the root cause (spam campaign, compromised account,
open relay), remediate it, then request delisting from the affected DNSBL
operators.

---

### SMTP Connect

**What it checks:** The mail server is reachable and responds with a valid
`220` banner.  The probe starts on **port 25** (RFC 5321); if the connection is
refused, times out, or the banner read fails (firewall accepts TCP then drops
the connection), it automatically retries on port **587** (RFC 6409) then
**465** (RFC 8314) before declaring failure.

**Why CRITICAL:**  
If the server is unreachable on all three ports, no inbound mail can be
delivered.  This check only generates a CRITICAL finding when it fails; a
successful connection is informational.

**Remediation:** Verify that at least one of TCP ports 25, 587, or 465 is
reachable from the public internet, that the MTA process is running, and that
the `220` greeting is RFC 5321-compliant.

### SMTP Port Fallback

**What it checks:** Records which port was actually used when port 25 was
unavailable and a fallback port succeeded.

**Severity:** `INFO` — no penalty points.

**Note:** Port 25 being blocked does not affect deliverability if the server
accepts connections on a fallback port, but it is non-standard for an MX server
and may indicate a misconfigured firewall or hosting provider restriction.

---

## HIGH — 10 pts each

HIGH findings indicate significant security gaps.  A single HIGH finding keeps
the grade at A (10 pts); three HIGH findings push the domain to B (30 pts
crosses the C boundary, so two HIGHs = B at 20 pts).  These checks cover
controls that materially reduce the attack surface but whose absence does not
immediately break email delivery.

### DKIM Base Node

**What it checks:** The base node `_domainkey.<domain>` returns a non-NXDOMAIN
response, confirming that DKIM signing infrastructure has been set up for the
domain (RFC 6376, RFC 2308).

**Why HIGH (not CRITICAL):**  
DKIM is a key authentication layer but its absence alone does not break delivery
— mail will still flow.  However, without DKIM, DMARC `adkim=strict` alignment
cannot pass, weakening anti-spoofing protection.  Large mailbox providers
increasingly require DKIM for bulk mail acceptance.  The check is at HIGH rather
than CRITICAL because DMARC can still enforce policy via SPF alignment, meaning
a limited form of protection remains.

**Remediation:** Generate a DKIM key pair, publish the public key as a `TXT`
record at `<selector>._domainkey.<domain>`, and configure your MTA to sign
outgoing messages with the private key.

---

### STARTTLS

**What it checks:** The SMTP server advertises the `STARTTLS` extension in its
EHLO response.

**Why HIGH:**  
STARTTLS (RFC 3207) enables opportunistic TLS for SMTP connections, protecting
message content in transit from passive interception.  Without STARTTLS, all
SMTP traffic is sent in cleartext and is trivially readable by any
network-level attacker between the sending and receiving servers.

**Remediation:** Enable STARTTLS on the MTA and obtain a valid certificate for
the server hostname.

---

### MTA-STS DNS Record

**What it checks:** A valid `_mta-sts.<domain>` TXT record exists with a
correctly formatted `id=` field.

**Why HIGH:**  
MTA-STS (RFC 8461) upgrades opportunistic TLS to mandatory TLS enforcement.
Without an MTA-STS DNS record, senders cannot discover the policy file and
opportunistic TLS downgrade attacks (STARTTLS stripping) remain possible.  The
DNS record is the discovery mechanism — its absence means the policy is never
enforced regardless of the policy file content.

**Remediation:** Publish a `v=STSv1; id=<timestamp>` record at
`_mta-sts.<domain>` and host a valid policy file at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`.

---

### Policy File (MTA-STS)

**What it checks:** The MTA-STS policy file is reachable, parseable, and
contains a valid `mx:` list that matches the domain's actual MX records.

**Why HIGH:**  
If the policy file cannot be fetched or the `mx:` list does not match the
server's certificate, MTA-STS-enforcing senders will fail to deliver mail.
This is a strict enforcement failure with real deliverability consequences.

**Remediation:** Ensure the HTTPS endpoint at
`https://mta-sts.<domain>/.well-known/mta-sts.txt` is reachable and that all
MX hostnames match the certificate's SANs.

---

### Policy Mode (MTA-STS)

**What it checks:** The `mode:` field in the MTA-STS policy file.

**Why HIGH:**  
`mode: testing` offers no protection — senders observe but do not enforce the
policy.  `mode: none` is a published signal to disable enforcement.  Only
`mode: enforce` provides the actual TLS downgrade protection that MTA-STS was
designed for.  A `testing` or `none` mode policy generates a HIGH finding
because the deployment exists but enforcement is deliberately or accidentally
disabled.

**Remediation:** Change `mode: testing` to `mode: enforce` once you have
confirmed all MX servers present valid, trusted TLS certificates.

---

### Policy (p=) — DMARC

**What it checks:** The DMARC `p=` tag value.

**Why HIGH:**  
`p=none` means receiving servers take no action when DMARC alignment fails —
the policy is purely observational.  This leaves the domain fully exposed to
spoofing attacks (lookalike domain fraud, BEC).  The finding is HIGH rather than
CRITICAL because the DMARC record exists (avoiding the CRITICAL penalty) and the
`rua=` reporting pipeline can be active.

**Remediation:** Analyse DMARC aggregate reports (`rua=`), resolve any
legitimate authentication failures, then move to `p=quarantine` followed by
`p=reject`.

---

### Cipher Suites

**What it checks:** The cipher suites accepted by the SMTP server, graded
against the [NCSC-NL TLS guidelines](https://www.ncsc.nl/en/transport-layer-security-tls/security-guidelines-for-transport-layer-security-2025-05).

**Why HIGH (escalates to CRITICAL for INSUFFICIENT):**  
Weak or broken cipher suites compromise the confidentiality of TLS sessions.
Phase-out suites (e.g. 3DES, RSA key exchange) are HIGH; INSUFFICIENT suites
(NULL cipher, anonymous, RC4, export ciphers) indicate a fundamental TLS
misconfiguration and are escalated to CRITICAL because they provide no
meaningful security.

**Remediation:** Disable Phase-out and Insufficient cipher suites.  Prefer
ECDHE+AES-GCM suites (TLS 1.3 includes only Good suites by design).

---

### Cipher Order

**What it checks:** Whether the server enforces its own cipher preference and
whether that preference follows the recommended ordering (Good → Sufficient →
Phase-out).

**Why HIGH:**  
If the server does not enforce cipher order, a downgrade attack can force a
weaker cipher even if strong ciphers are available.  Correct server-side
preference ensures the strongest mutually supported cipher is always selected.

**Remediation:** Enable `ssl_prefer_server_ciphers on` (nginx/Postfix) or
equivalent and order ciphers from strongest to weakest.

---

### TLS Versions

**What it checks:** Which TLS protocol versions the server accepts.

**Why HIGH (escalates to CRITICAL for INSUFFICIENT):**  
TLS 1.0 and 1.1 are deprecated (RFC 8996) and contain known weaknesses (BEAST,
POODLE, SLOTH).  Their presence is HIGH.  An INSUFFICIENT finding (e.g. SSLv3
accepted) is escalated to CRITICAL because SSLv3 is trivially broken (POODLE,
CVE-2014-3566).

**Remediation:** Disable TLS 1.0 and TLS 1.1.  Support TLS 1.2 (minimum) and
TLS 1.3.

---

### SPF Policy

**What it checks:** The `all` qualifier in the SPF record (`+all`, `?all`,
`~all`, `-all`).

**Why HIGH:**  
`+all` or `?all` allows any sender to pass SPF — it is effectively no
protection at all.  `~all` (soft fail) is informational in many configurations
but a WARNING.  Only `-all` (hard fail) provides meaningful enforcement.  A
permissive `all` qualifier undermines the entire SPF deployment.

**Remediation:** Replace `+all` or `?all` with `-all`.  If soft fail is
temporarily necessary, plan migration to `-all`.

---

### DNS Lookup Count (SPF)

**What it checks:** The number of DNS lookups required to fully resolve the SPF
record, including all `include:`, `a`, `mx`, `ptr`, and `redirect=` mechanisms.

**Why HIGH:**  
RFC 7208 §4.6.4 limits SPF resolution to **10 DNS lookups**.  Exceeding this
limit causes receiving servers to return a `permerror`, which most DMARC
implementations treat as an alignment failure — effectively the same outcome as
no SPF record.

**Remediation:** Reduce the number of `include:` mechanisms.  Use SPF flattening
tools to inline IP ranges directly.  Consolidate sending services where possible.

---

### Multiple SPF Records

**What it checks:** Whether more than one SPF `TXT` record exists at the domain.

**Why HIGH:**  
RFC 7208 §3.2 states that a domain MUST NOT have more than one SPF record.
Multiple records result in a `permerror` during evaluation, which invalidates
SPF and can cause DMARC failures.

**Remediation:** Remove all but one SPF record.  Merge multiple policies into a
single `v=spf1 … all` record.

---

### DANE – Certificate Match

**What it checks:** Whether the TLS certificate presented by the server matches
the TLSA record fingerprint published in DNS.

**Why HIGH:**  
When DANE is deployed (DNSSEC-signed `_25._tcp.<mx-host>` TLSA records), a
certificate mismatch means the server is presenting a certificate that its own
DNS says should not be trusted.  DANE-validating senders will refuse the
connection, causing non-delivery.  This is only relevant when DANE is actively
deployed; the check does not penalise domains that have not deployed DANE.

**Remediation:** Re-generate the TLSA record fingerprint to match the current
certificate, or revert to the certificate whose fingerprint is published.

---

### Certificate Public Key / Domain Match / Signature

**What they check:** The TLS certificate's public key strength, whether the
server hostname matches a Subject Alternative Name (SAN) or Common Name, and
whether the signature algorithm is modern (e.g. SHA-256 vs SHA-1).

**Why HIGH:**  
A certificate that does not match the server hostname means MTA-STS-enforcing
senders will reject the connection.  A weak public key (e.g. RSA-1024) or
deprecated signature (SHA-1) lowers the cryptographic bar below recommended
minimums.

**Remediation:** Issue a new certificate with RSA-2048+ (or EC P-256+) key,
SHA-256+ signature, and a SAN that matches the server's FQDN.

---

## MEDIUM — 3 pts each

MEDIUM findings are operational and compliance gaps.  They do not represent an
immediate security risk but represent best-practice shortfalls that can reduce
defence-in-depth or cause minor deliverability issues.  Multiple MEDIUM findings
can accumulate enough penalty to affect the grade (14 × MEDIUM = 42 pts = F),
so they should not be ignored indefinitely.

### BIMI Record

**What it checks:** A valid BIMI `TXT` record at `default._bimi.<domain>`.

**Why MEDIUM:**  
BIMI (Brand Indicators for Message Identification) displays a verified logo in
supporting email clients (Gmail, Apple Mail, Yahoo).  It is a marketing and
trust-signalling feature rather than a security control.  Missing BIMI does not
affect deliverability or authentication, but it does mean the organisation
cannot take advantage of enhanced brand trust indicators.  BIMI requires
`p=quarantine` or `p=reject` DMARC, so deploying it also indirectly incentivises
stronger DMARC policy.

**Remediation:** Publish a BIMI record pointing to an SVG logo.  Optionally
obtain a Verified Mark Certificate (VMC) for the `a=` field to unlock Gmail
display.

---

### CAA Records

**What it checks:** `CAA` DNS records at the domain and its parent zones (RFC
8659), restricting which Certificate Authorities may issue certificates for the
domain.

**Why MEDIUM:**  
CAA records constrain mis-issuance: if an attacker tricks a CA into issuing a
fraudulent certificate for the domain, CAA-enforcing CAs will refuse.  The
protection is best-effort (only CAs that check CAA honour the restriction), but
publishing CAA is a low-effort defence-in-depth measure.

**Remediation:** Add `CAA 0 issue "letsencrypt.org"` (or whichever CA you use)
records for the domain and relevant MX hostnames.

---

### DANE – TLSA Existence

**What it checks:** Whether `_25._tcp.<mx-host>` TLSA records are published
(RFC 6698).

**Why MEDIUM:**  
DANE/TLSA enables SMTP servers to authenticate the remote server's certificate
using DNSSEC-signed DNS records — independent of the CA PKI.  It provides a
second layer of certificate validation that is immune to rogue CA mis-issuance.
DANE deployment requires DNSSEC on the MX host, which is itself a prerequisite
that limits adoption, hence MEDIUM rather than HIGH.

**Remediation:** Deploy DNSSEC on the MX host zone, then publish TLSA records
using usage type 3 (DANE-EE) for the leaf certificate fingerprint.

---

### DANE – Matching Type / Rollover Scheme

**What they check:** Whether the TLSA record uses a secure matching type
(SHA-256 or SHA-512 rather than full certificate; RFC 7671 §5.1) and whether a
rollover scheme is in place (two TLSA records present during certificate
renewal).

**Why MEDIUM:**  
Matching type 0 (full certificate match) breaks DANE validation on any
certificate renewal unless the TLSA record is updated simultaneously — a
fragile operational dependency.  Missing rollover records create a window during
certificate rotation where DANE-validating senders will be refused.  These are
operational robustness issues rather than active security gaps.

**Remediation:** Use matching type 1 (SHA-256) or type 2 (SHA-512).  Publish
both the current and next certificate fingerprints during planned renewal
windows.

---

### DNSSEC

**What it checks:** Whether the domain and its MX hosts have a valid DNSSEC
chain of trust from the root (`.`) through the TLD to the domain.

**Why MEDIUM:**  
DNSSEC prevents DNS cache-poisoning attacks (Kaminsky attack) and is a
prerequisite for DANE.  Without DNSSEC, SPF, DMARC, and MX records can
potentially be spoofed at the DNS level by a network-positioned attacker.  The
finding is MEDIUM rather than HIGH because exploiting unsigned DNS requires a
network-level attacker (MitM or DNS poisoning), which is a harder attack than
protocol-level spoofing.

**Remediation:** Enable DNSSEC signing with the domain registrar and/or DNS
provider.  Ensure DS records are published in the parent TLD zone.

---

### Duplicate Priorities (MX)

**What it checks:** Whether multiple MX records share the same priority value.

**Why MEDIUM:**  
Duplicate priorities are not forbidden by RFC 5321 but indicate an
inconsistency in the MX configuration.  Equal-priority MX hosts share load
equally; this may be intentional, but is frequently an oversight that affects
routing predictability.

**Remediation:** Review MX records and assign distinct priority values unless
equal-priority load-balancing is explicitly desired.

---

### Banner FQDN

**What it checks:** Whether the `220` greeting banner includes the server's
fully qualified domain name (RFC 5321 §4.1.3).

**Why MEDIUM:**  
RFC 5321 requires the `220` banner to include the FQDN.  Servers that omit it
or use a bare IP violate the standard.  Some strict SMTP implementations will
refuse the connection.  This is a compliance issue rather than an active
security gap.

**Remediation:** Configure the MTA's hostname/FQDN setting to use the server's
fully qualified domain name.

---

### EHLO Domain

**What it checks:** Whether the EHLO response names the server as a valid FQDN
rather than a bare IP or invalid domain literal (RFC 5321 §4.1.1.1).

**Why MEDIUM:**  
Same rationale as Banner FQDN — RFC compliance and interoperability rather than
active attack surface.

**Remediation:** Set the MTA's `myhostname` or equivalent directive to a valid
FQDN with a corresponding A/AAAA record.

---

### TLSRPT Record

**What it checks:** A valid `TXT` record at `_smtp._tls.<domain>` (RFC 8460).

**Why MEDIUM:**  
TLS Reporting enables sending servers to report TLS connection failures (STARTTLS
unavailability, certificate errors, MTA-STS violations) back to the domain
operator.  Without TLSRPT, TLS-related delivery failures are invisible.  The
finding is MEDIUM because the absence of reporting does not introduce a
vulnerability — it only means failures go undetected.

**Remediation:** Publish a `v=TLSRPTv1; rua=mailto:tlsrpt@example.com` record
and monitor the reports.

---

### Reverse DNS (PTR)

**What it checks:** Whether the MX server's IP address has a valid PTR record
that resolves back to the same IP (forward-confirmed reverse DNS, FCrDNS).

**Why MEDIUM:**  
Many receiving mail servers perform PTR lookups and reject or penalise mail from
IPs without valid reverse DNS.  This is a deliverability best practice rather
than a strict security control, hence MEDIUM.

**Remediation:** Ask the IP address owner (hosting provider, ISP) to configure a
PTR record for the server's IP pointing to its FQDN.

---

## Suppressed — informational only

The following checks are always recorded in the report but **never generate an
action item** and **never affect the grade**, regardless of their value.
They are included for visibility and operational awareness.

| Check name                       | Reason suppressed                                                                                          |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| ESMTP Extensions                 | Presence of SIZE, PIPELINING, 8BITMIME, SMTPUTF8 is informational; absence is not a security gap          |
| VRFY Command                     | RFC 5321 §3.5.3 recommends disabling VRFY for privacy; both enabled and disabled states are acceptable     |
| TLS Compression                  | Deflate/zlib disable state (CRIME, CVE-2012-4929) is expected and OK; no action needed when absent          |
| Secure Renegotiation             | Informational — most modern servers support RFC 5746 by default                                             |
| Client-Initiated Renegotiation   | Informational — noted but not penalised                                                                    |
| Key Exchange                     | ECDHE curve and DHE group details are recorded; only extreme weakness would warrant action (handled elsewhere) |
| Hash Function (Key Exchange)     | SHA-1/MD5 in key exchange is deprecated but rarely exploitable in TLS 1.2 key exchange specifically          |
| Tag Order (v=)                   | Ordering conformance noted for SPF/DMARC/TLSRPT; not a security gap                                        |
| SPF Version                      | `v=spf1` presence is informational                                                                         |
| SPF Include Resolution           | Detailed trace of include: resolution chain; informational                                                 |
| Nested +all in include:          | Flagged as WARNING in the check output; source SPF domain controls the policy                               |
| Void Lookup Count                | RFC 7208 §4.6.4 void-lookup limit; informational tracking                                                  |
| ptr Mechanism                    | RFC 7208 §5.5 deprecates `ptr`; flagged as WARNING in check output                                        |
| Subdomain Policy (sp=)           | DMARC subdomain policy; recorded but policy choice belongs to domain owner                                  |
| Percentage (pct=)                | DMARC rollout percentage; informational                                                                    |
| Forensic Options (fo=)           | DMARC failure reporting detail; operational choice                                                         |
| Reporting Interval (ri=)         | DMARC report interval; operational choice                                                                  |
| Record ID (id=)                  | MTA-STS record identifier; informational                                                                   |
| Policy File Content-Type         | MTA-STS `text/plain` conformance; minor RFC compliance note                                               |
| Policy File Line Endings         | MTA-STS CRLF conformance; minor RFC compliance note                                                       |
| Policy Version                   | MTA-STS `version: STSv1` field; informational                                                             |
| Unknown Tags                     | Unrecognised tags in BIMI/TLSRPT/MTA-STS records; informational warning                                   |
| Reporting URI                    | BIMI/DMARC/TLSRPT reporting address; operational choice                                                    |
| Logo URL (l=)                    | BIMI logo URL; operational detail                                                                          |
| DNS Version                      | DNS query metadata; informational                                                                           |
| DANE – DNSSEC Prerequisite       | Noted when DANE records exist but DNSSEC is not signed; DNSSEC itself carries the MEDIUM finding           |
| TLS Inspection                   | Aggregate summary label; individual cipher/version checks carry the penalties                              |

---

## Escalation rules

Two runtime escalation rules override the static severity table:

1. **Cipher Suites INSUFFICIENT → CRITICAL**  
   If any negotiated cipher suite has status `INSUFFICIENT` (NULL cipher,
   anonymous key exchange, RC4, export ciphers), the Cipher Suites finding is
   escalated from HIGH to CRITICAL.  These suites provide no effective security.

2. **TLS Versions INSUFFICIENT → CRITICAL**  
   If the server accepts a TLS version rated INSUFFICIENT (SSLv3), the TLS
   Versions finding is escalated from HIGH to CRITICAL (POODLE, CVE-2014-3566).

---

## Reading the verdict panel

The panel title encodes the grade letter and rationale.
The table inside lists every action item sorted from most to least urgent
(`CRITICAL` → `HIGH` → `MEDIUM`).

```
╭─── Security Verdict  C  1 critical, 1 high, 1 medium issue(s) found (38 penalty point(s)). ─────────────────────╮
│                                                                                                                 │
│  Priority    Action                                                                                             │
│ ─────────────────────────────────────────────────────────────────────────────────────────────────────────────── │
│  CRITICAL    Fix SPF Record: No SPF record found at example.com.                                                │
│  HIGH        Review Policy (p=): p=none — DMARC is in monitoring mode only, no enforcement.                     │
│  MEDIUM      Fix TLSRPT Record: No TLSRPT record found at _smtp._tls.example.com.                               │
│                                                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

The panel border colour reflects the grade: bright green for A+/A, yellow for B/C,
red for D, bright red for F.

Action verbs indicate the type of issue:

| Verb        | Meaning                                          |
| ----------- | ------------------------------------------------ |
| **Fix**     | Missing or broken (`NOT_FOUND` / `ERROR`)        |
| **Review**  | Suboptimal policy (`WARNING`)                    |
| **Upgrade** | Deprecated or below minimum (`PHASE_OUT` / `INSUFFICIENT`) |
| **Improve** | Present but below best practice                  |

Duplicate findings across multiple MX servers are collapsed to a single action
item to avoid noise — for example, a STARTTLS issue on three MX servers appears
only once.
