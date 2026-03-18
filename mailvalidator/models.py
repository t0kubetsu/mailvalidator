"""Shared result dataclasses and the :class:`Status` enum for mailvalidator.

Every check function returns one of the typed ``*Result`` objects defined
here.  :class:`CheckResult` is the universal single-check carrier; the
``*Result`` classes collect zero or more of them alongside raw record data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Security / conformance verdict for a single check item.

    Ordered roughly from best to worst:

    - ``GOOD`` / ``OK`` – fully compliant.
    - ``SUFFICIENT`` – acceptable but not ideal (TLS-grade vocabulary).
    - ``INFO`` / ``NA`` – informational; no pass/fail verdict.
    - ``WARNING`` – potential issue; action recommended.
    - ``PHASE_OUT`` – deprecated; migration required.
    - ``INSUFFICIENT`` – below the minimum acceptable threshold.
    - ``ERROR`` – definite misconfiguration or failure.
    - ``NOT_FOUND`` – expected record or resource is absent.
    """

    OK = "OK"
    GOOD = "GOOD"
    SUFFICIENT = "SUFFICIENT"
    INFO = "INFO"
    NA = "N/A"
    WARNING = "WARNING"
    PHASE_OUT = "PHASE_OUT"
    INSUFFICIENT = "INSUFFICIENT"
    ERROR = "ERROR"
    NOT_FOUND = "NOT_FOUND"


@dataclass
class CheckResult:
    """Result of a single diagnostic check.

    :param name: Short human-readable label shown in the report table.
    :param status: Overall verdict for this check.
    :param value: Optional one-line summary value (e.g. ``"TLSv1.3"``).
    :param details: Zero or more lines of additional context.
    :param raw: Optional raw data dict for programmatic consumers; not rendered.
    """

    name: str
    status: Status
    value: str = ""
    details: list[str] = field(default_factory=list)
    raw: dict | None = None


# ---------------------------------------------------------------------------
# DNS / MX models
# ---------------------------------------------------------------------------


@dataclass
class MXRecord:
    """A single MX resource record with resolved IP addresses.

    :param priority: MX preference value (lower = higher priority).
    :param exchange: Fully-qualified mail exchanger hostname.
    :param ip_addresses: Resolved A/AAAA addresses for the exchanger.
    """

    priority: int
    exchange: str
    ip_addresses: list[str] = field(default_factory=list)


@dataclass
class MXResult:
    """Aggregated MX lookup result for a domain.

    :param domain: The queried domain name.
    :param records: MX records sorted by priority (ascending).
    :param authoritative_ns: IP addresses of the authoritative name servers.
    :param checks: Individual :class:`CheckResult` items.
    """

    domain: str
    records: list[MXRecord] = field(default_factory=list)
    authoritative_ns: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# TLS / SMTP models
# ---------------------------------------------------------------------------


@dataclass
class TLSDetails:
    """Deep TLS session metadata collected during an SMTP STARTTLS probe.

    Most fields are populated by ``_probe_tls()`` in ``smtp.py``.

    ``cert_trusted`` uses three-valued logic:

    - ``True``  – chain verified against the system trust store.
    - ``False`` – chain broken or self-signed (``SSLCertVerificationError``).
    - ``None``  – verification was not possible (bare IP or connection failure).
    """

    tls_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0

    # Certificate fields
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_san: list[str] = field(default_factory=list)
    cert_not_after: str = ""
    cert_sig_alg: str = ""
    cert_pubkey_type: str = ""  #: ``"RSA"`` or ``"EC"``
    cert_pubkey_bits: int = 0  #: RSA key size in bits
    cert_pubkey_curve: str = ""  #: EC curve name (e.g. ``"secp256r1"``)
    cert_trusted: bool | None = None

    # Key exchange
    dh_group: str = ""  #: ECDHE curve or FFDHE group name
    dh_bits: int = 0

    # Connection properties
    compression: str = ""  #: ``""`` = none; ``"zlib"`` / ``"deflate"`` if present
    secure_renegotiation: bool | None = None
    server_cipher_order: bool | None = None

    # Accumulated cipher lists (populated by ``_check_cipher``)
    offered_ciphers: list[str] = field(default_factory=list)

    # Internal stash fields used across checks (not for external consumption)
    dane_tlsa_records: list[str] = field(default_factory=list)
    caa_records: list[str] = field(default_factory=list)


@dataclass
class SMTPDiagResult:
    """All SMTP diagnostic results for a single mail server host.

    :param host: Hostname or IP address of the mail server.
    :param port: TCP port that was probed.
    :param banner: SMTP greeting banner string.
    :param reverse_dns: PTR record for the server's IP, or ``""`` if absent.
    :param open_relay: ``True`` if the server accepted an open-relay test.
    :param response_time_ms: TCP connect latency in milliseconds.
    :param tls_supported: ``True`` if STARTTLS was advertised in EHLO.
    :param tls: Deep TLS session details, or ``None`` if STARTTLS was absent.
    :param checks: Individual :class:`CheckResult` items.
    """

    host: str
    port: int
    banner: str = ""
    reverse_dns: str = ""
    open_relay: bool = False
    response_time_ms: float = 0.0
    tls_supported: bool = False
    tls: TLSDetails | None = None
    checks: list[CheckResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Email authentication record models
# ---------------------------------------------------------------------------


@dataclass
class DKIMResult:
    """Result of the DKIM base-node DNS conformance check.

    Validates that ``_domainkey.<domain>`` answers NOERROR (RFC 2308 empty
    non-terminal), which is required for receivers to discover DKIM support
    without knowing the selector in advance.

    :param domain: The queried domain name.
    :param checks: Individual :class:`CheckResult` items.
    """

    domain: str
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class BIMIResult:
    """Result of a BIMI record lookup and validation.

    :param domain: The queried domain name.
    :param record: Raw BIMI TXT record string, or ``""`` if not found.
    :param checks: Individual :class:`CheckResult` items.
    """

    domain: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class SPFResult:
    """Result of an SPF record lookup and policy validation.

    :param domain: The queried domain name.
    :param record: Raw SPF TXT record string, or ``""`` if not found.
    :param checks: Individual :class:`CheckResult` items.
    """

    domain: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class DMARCResult:
    """Result of a DMARC record lookup and policy validation.

    :param domain: The queried domain name.
    :param record: Raw DMARC TXT record string, or ``""`` if not found.
    :param checks: Individual :class:`CheckResult` items.
    """

    domain: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class TLSRPTResult:
    """Result of an SMTP TLS Reporting (TLSRPT) record check.

    :param domain: The queried domain name.
    :param record: Raw TLSRPT TXT record string, or ``""`` if not found.
    :param checks: Individual :class:`CheckResult` items.
    """

    domain: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class MTASTSResult:
    """Result of an MTA-STS DNS record and policy file check.

    :param domain: The queried domain name.
    :param dns_record: Raw MTA-STS TXT record string, or ``""`` if not found.
    :param policy: Parsed key/value pairs from the fetched policy file.
    :param checks: Individual :class:`CheckResult` items.
    """

    domain: str
    dns_record: str = ""
    policy: dict[str, str] = field(default_factory=dict)
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class BlacklistResult:
    """Result of a DNS blacklist check for a single IP address.

    :param ip: The IP address that was checked.
    :param total_checked: Number of DNSBL zones queried.
    :param listed_on: Sorted list of zones where the IP was found listed.
    :param checks: Individual :class:`CheckResult` items.
    """

    ip: str
    total_checked: int = 0
    listed_on: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


@dataclass
class FullReport:
    """Aggregated result of all checks run by :func:`mailvalidator.assessor.assess`.

    Individual fields are ``None`` or empty list when the corresponding check
    was skipped or produced no result.

    :param domain: The assessed domain name.
    :param mx: MX record lookup results.
    :param smtp: SMTP diagnostic results for each probed MX server.
    :param spf: SPF record validation results.
    :param dmarc: DMARC record validation results.
    :param dkim: DKIM base-node conformance check results.
    :param bimi: BIMI record validation results.
    :param tlsrpt: TLSRPT record validation results.
    :param mta_sts: MTA-STS DNS record and policy file results.
    :param blacklist: DNS blacklist check results for the primary MX IP.
    """

    domain: str
    mx: MXResult | None = None
    smtp: list[SMTPDiagResult] = field(default_factory=list)
    spf: SPFResult | None = None
    dmarc: DMARCResult | None = None
    dkim: DKIMResult | None = None
    bimi: BIMIResult | None = None
    tlsrpt: TLSRPTResult | None = None
    mta_sts: MTASTSResult | None = None
    blacklist: BlacklistResult | None = None
