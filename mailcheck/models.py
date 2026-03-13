"""Shared result models for mailcheck checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    ERROR = "ERROR"
    INFO = "INFO"
    NOT_FOUND = "NOT_FOUND"
    PHASE_OUT = "PHASE_OUT"
    INSUFFICIENT = "INSUFFICIENT"
    GOOD = "GOOD"
    SUFFICIENT = "SUFFICIENT"
    NA = "N/A"


@dataclass
class CheckResult:
    """Generic result for a single diagnostic item."""

    name: str
    status: Status
    value: str = ""
    details: list[str] = field(default_factory=list)
    raw: dict | None = None


@dataclass
class MXRecord:
    priority: int
    exchange: str
    ip_addresses: list[str] = field(default_factory=list)


@dataclass
class MXResult:
    domain: str
    records: list[MXRecord] = field(default_factory=list)
    authoritative_ns: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class TLSDetails:
    """Structured TLS inspection results for a single SMTP connection."""

    tls_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_san: list[str] = field(default_factory=list)
    cert_not_after: str = ""
    cert_sig_alg: str = ""
    cert_pubkey_type: str = ""  # "RSA" | "EC"
    cert_pubkey_bits: int = 0  # RSA key length
    cert_pubkey_curve: str = ""  # EC curve name
    cert_trusted: bool = False
    dane_tlsa_records: list[str] = field(default_factory=list)
    caa_records: list[str] = field(default_factory=list)
    compression: str = ""  # "" = none, "zlib", etc.
    secure_renegotiation: bool | None = None
    dh_group: str = ""  # ECDHE curve or FFDHE group name
    dh_bits: int = 0
    server_cipher_order: bool | None = None
    offered_ciphers: list[str] = field(default_factory=list)


@dataclass
class SMTPDiagResult:
    host: str
    port: int
    banner: str = ""
    reverse_dns: str = ""
    open_relay: bool = False
    response_time_ms: float = 0.0
    tls_supported: bool = False
    tls: TLSDetails | None = None
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class DKIMResult:
    domain: str
    selector: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class BIMIResult:
    domain: str
    record: str = ""
    selector: str = "default"
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class TLSRPTResult:
    domain: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class BlacklistResult:
    ip: str
    total_checked: int = 0
    listed_on: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class SPFResult:
    domain: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class DMARCResult:
    domain: str
    record: str = ""
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class MTASTSResult:
    domain: str
    dns_record: str = ""
    policy: dict[str, str] = field(default_factory=dict)
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class FullReport:
    domain: str
    mx: MXResult | None = None
    smtp: list[SMTPDiagResult] = field(default_factory=list)
    dkim: DKIMResult | None = None
    bimi: BIMIResult | None = None
    tlsrpt: TLSRPTResult | None = None
    blacklist: BlacklistResult | None = None
    spf: SPFResult | None = None
    dmarc: DMARCResult | None = None
    mta_sts: MTASTSResult | None = None
