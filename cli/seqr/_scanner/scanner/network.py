"""
TLS/certificate network scanner using sslyze.

For each domain:
1. Connect and get TLS certificate chain
2. Run cipher suite enumeration (all TLS versions + elliptic curves)
3. Extract key exchange from ephemeral_key.type_name / curve_name
4. Parse cert: algorithm, key size, expiry, issuer, SANs
5. Return structured DomainScanResult

Key exchange extraction uses sslyze's ephemeral_key object, not cipher name parsing.
TLS 1.3 cipher names (TLS_AES_*) never encode the key exchange; use ephemeral_key.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import ssl as _ssl_module
import time
import urllib.request as _urllib_req
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa
from sslyze import (
    ProtocolWithOpportunisticTlsEnum,
    Scanner,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanRequest,
)
from sslyze.errors import ConnectionToServerFailed, ServerHostnameCouldNotBeResolved
from sslyze.plugins.scan_commands import ScanCommand

# STARTTLS / wrapped-protocol support → (sslyze enum, default port, openssl -starttls name).
# SMTP/IMAP/POP3 reuse the full TLS analysis; POSTGRES covers database TLS.
_WRAPPED_PROTOCOLS: dict[str, tuple] = {
    "smtp":     (ProtocolWithOpportunisticTlsEnum.SMTP, 587, "smtp"),
    "imap":     (ProtocolWithOpportunisticTlsEnum.IMAP, 143, "imap"),
    "pop3":     (ProtocolWithOpportunisticTlsEnum.POP3, 110, "pop3"),
    "postgres": (ProtocolWithOpportunisticTlsEnum.POSTGRES, 5432, "postgres"),
}

from ..engines.classifier import (
    AlgorithmClassification,
    classify_algorithm,
    classify_tls_version,
    recommended_algorithm,
)

logger = logging.getLogger(__name__)


def _normalize_domain(domain: str) -> str:
    """Strip http:// or https:// prefix and trailing slashes/paths."""
    d = domain.strip()
    for prefix in ("https://", "http://"):
        if d.lower().startswith(prefix):
            d = d[len(prefix):]
    return d.split("/")[0].split("?")[0]


def infer_shelf_life(domain: str) -> str:
    """Infer data shelf life from domain name keywords.

    Financial and healthcare domains carry long-lived regulated data —
    critical for correct HNDL risk assessment.
    """
    d = domain.lower()
    # Ephemeral: session/auth flows — tokens expire in minutes/hours
    if any(k in d for k in (
        "auth", "login", "otp", "token", "session", "sso", "oauth", "logout",
    )):
        return "ephemeral"
    # Long-lived: financial services — transaction records kept 5-7 years by law
    if any(k in d for k in (
        "pay", "payment", "transaction", "billing", "invoice", "checkout",
        "bank", "banking", "finance", "fintech", "wallet", "loan", "credit",
        "debit", "transfer", "remit", "trading", "invest", "insurance",
        "mortgage", "pension", "tax", "razorpay", "stripe", "paytm",
    )):
        return "long"
    # Long-lived: health/medical records — HIPAA requires 6+ year retention
    if any(k in d for k in (
        "health", "record", "history", "archive", "medical",
        "hospital", "patient", "clinical", "pharma", "diagnostic", "ehr",
    )):
        return "long"
    # Permanent: government/critical infrastructure — highest classification
    if any(k in d for k in (
        "gov", "mil", "government", "ministry", "federal", "national",
        "nic.", ".gov.", "india.gov",
    )):
        return "permanent"
    return "short"


# ---------------------------------------------------------------------------
# Cloud/CDN detection constants
# ---------------------------------------------------------------------------

_CLOUD_NETWORKS = [
    ipaddress.ip_network("52.0.0.0/8"),   # AWS
    ipaddress.ip_network("54.0.0.0/8"),   # AWS
    ipaddress.ip_network("3.0.0.0/8"),    # AWS
    ipaddress.ip_network("34.0.0.0/8"),   # GCP
    ipaddress.ip_network("35.0.0.0/8"),   # GCP
    ipaddress.ip_network("13.0.0.0/8"),   # Azure
    ipaddress.ip_network("40.0.0.0/8"),   # Azure
]

_CDN_INDICATORS = frozenset({
    "cloudflare", "fastly", "akamai", "incapsula", "sucuri",
    "cloudfront", "cdn77", "stackpath", "bunnycdn", "azureedge",
})

# Reverse-DNS PTR patterns → provider display name
_REVERSE_DNS_CDN: list[tuple[str, str]] = [
    ("fastly.net",            "Fastly"),
    ("cloudfront.net",        "Amazon CloudFront"),
    ("akamai.net",            "Akamai"),
    ("akadns.net",            "Akamai"),
    ("edgesuite.net",         "Akamai"),
    ("edgekey.net",           "Akamai"),
    ("cloudflare.com",        "Cloudflare"),
    ("cloudflare.net",        "Cloudflare"),   # Cloudflare PTR records use .net, not .com
    ("azureedge.net",         "Azure CDN"),
    ("msecnd.net",            "Azure CDN"),
    ("googleusercontent.com", "Google Cloud CDN"),
    ("googlevideo.com",       "Google Cloud CDN"),
    ("imperva.com",           "Imperva"),
    ("incapsula.com",         "Imperva"),
    ("sucuri.net",            "Sucuri"),
    ("llnwd.net",             "Limelight Networks"),
]

# Published CDN IP ranges for CIDR-based detection (fallback when PTR is absent/unhelpful)
# Sources: cloudflare.com/ips, fastly.com/documentation/reference/ip-addresses
_CDN_IP_RANGES: list[tuple[ipaddress.IPv4Network, str]] = [
    # Cloudflare — https://www.cloudflare.com/ips-v4
    (ipaddress.ip_network("103.21.244.0/22"),   "Cloudflare"),
    (ipaddress.ip_network("103.22.200.0/22"),   "Cloudflare"),
    (ipaddress.ip_network("103.31.4.0/22"),     "Cloudflare"),
    (ipaddress.ip_network("104.16.0.0/13"),     "Cloudflare"),
    (ipaddress.ip_network("104.24.0.0/14"),     "Cloudflare"),
    (ipaddress.ip_network("108.162.192.0/18"),  "Cloudflare"),
    (ipaddress.ip_network("131.0.72.0/22"),     "Cloudflare"),
    (ipaddress.ip_network("141.101.64.0/18"),   "Cloudflare"),
    (ipaddress.ip_network("162.158.0.0/15"),    "Cloudflare"),
    (ipaddress.ip_network("172.64.0.0/13"),     "Cloudflare"),
    (ipaddress.ip_network("173.245.48.0/20"),   "Cloudflare"),
    (ipaddress.ip_network("188.114.96.0/20"),   "Cloudflare"),
    (ipaddress.ip_network("190.93.240.0/20"),   "Cloudflare"),
    (ipaddress.ip_network("197.234.240.0/22"),  "Cloudflare"),
    (ipaddress.ip_network("198.41.128.0/17"),   "Cloudflare"),
    # Fastly (includes GitHub Pages: 185.199.108.0/22)
    (ipaddress.ip_network("185.199.108.0/22"),  "Fastly"),
    (ipaddress.ip_network("23.235.32.0/20"),    "Fastly"),
    (ipaddress.ip_network("43.249.72.0/22"),    "Fastly"),
    (ipaddress.ip_network("103.244.50.0/24"),   "Fastly"),
    (ipaddress.ip_network("103.245.222.0/23"),  "Fastly"),
    (ipaddress.ip_network("103.245.224.0/24"),  "Fastly"),
    (ipaddress.ip_network("104.156.80.0/20"),   "Fastly"),
    (ipaddress.ip_network("151.101.0.0/16"),    "Fastly"),
    (ipaddress.ip_network("157.52.64.0/18"),    "Fastly"),
    (ipaddress.ip_network("167.82.0.0/17"),     "Fastly"),
    (ipaddress.ip_network("199.27.72.0/21"),    "Fastly"),
    (ipaddress.ip_network("199.232.0.0/16"),    "Fastly"),
]

# HTTP response header signatures → provider display name
_HEADER_CDN: list[tuple[str, list[str]]] = [
    ("Cloudflare",        ["cf-ray", "cf-cache-status"]),
    ("Fastly",            ["x-served-by"]),
    ("Amazon CloudFront", ["x-amz-cf-id", "x-amz-cf-pop"]),
    ("Akamai",            ["x-check-cacheable", "x-akamai-request-id"]),
    ("Imperva",           ["x-iinfo"]),
    ("Sucuri",            ["x-sucuri-id"]),
    ("BunnyCDN",          ["bunnycdn-cache-status"]),
]

# Cert text indicator → display name
_CDN_DISPLAY: dict[str, str] = {
    "cloudflare":  "Cloudflare",
    "fastly":      "Fastly",
    "akamai":      "Akamai",
    "incapsula":   "Imperva (Incapsula)",
    "sucuri":      "Sucuri",
    "cloudfront":  "Amazon CloudFront",
    "cdn77":       "CDN77",
    "stackpath":   "StackPath",
    "bunnycdn":    "BunnyCDN",
    "azureedge":   "Azure CDN",
}


def _reverse_dns_cdn(ip: str) -> str:
    """Resolve PTR record for ip and match against known CDN hostnames."""
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        for pattern, name in _REVERSE_DNS_CDN:
            if pattern in hostname:
                return name
    except Exception:
        pass
    return ""


def _cidr_cdn(ip: str) -> str:
    """Match ip against published CDN CIDR ranges. Returns provider name or ''."""
    try:
        addr = ipaddress.ip_address(ip)
        for network, provider in _CDN_IP_RANGES:
            if addr in network:
                return provider
    except ValueError:
        pass
    return ""


def _http_header_cdn(domain: str, timeout: int = 3) -> str:
    """Send HTTPS HEAD request, inspect response headers for CDN signatures."""
    try:
        ctx = _ssl_module.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_module.CERT_NONE
        req = _urllib_req.Request(
            f"https://{domain}/",
            method="HEAD",
            headers={"User-Agent": "SeQrScanner/1.0"},
        )
        with _urllib_req.urlopen(req, timeout=timeout, context=ctx) as resp:
            hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
    except Exception:
        return ""

    for cdn_name, sig_headers in _HEADER_CDN:
        if any(h in hdrs for h in sig_headers):
            return cdn_name

    combined = " ".join([hdrs.get("via", ""), hdrs.get("server", ""), hdrs.get("x-cache", "")])
    for keyword, name in [
        ("fastly", "Fastly"), ("cloudflare", "Cloudflare"),
        ("cloudfront", "Amazon CloudFront"), ("akamai", "Akamai"),
        ("varnish", "Varnish Cache"),
    ]:
        if keyword in combined:
            return name
    return ""


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CertificateInfo:
    algorithm: str
    algorithm_family: str
    key_size: Optional[int]
    expiry_date: Optional[datetime]
    issuer: str
    subject: str
    serial: str
    san: list[str]
    is_expired: bool
    days_until_expiry: Optional[int]


@dataclass
class CipherSuiteInfo:
    name: str
    key_exchange: str
    authentication: str
    encryption: str
    tls_version: str


@dataclass
class DomainScanResult:
    domain: str
    port: int
    reachable: bool

    # TLS details
    tls_version: Optional[str] = None
    tls_version_classification: Optional[AlgorithmClassification] = None

    # Certificate
    cert: Optional[CertificateInfo] = None

    # Cipher / key exchange
    cipher_suite: Optional[str] = None
    key_exchange_algorithm: Optional[str] = None       # canonical name (X25519, ECDHE, RSA, DHE)
    key_exchange_classification: Optional[AlgorithmClassification] = None

    # Certificate algorithm classification
    cert_algorithm_classification: Optional[AlgorithmClassification] = None

    # PQC readiness
    pqc_hybrid_offered: bool = False    # X25519Kyber768 or similar hybrid in supported ciphers
    pqc_only_offered: bool = False      # Pure ML-KEM cipher offered
    hybrid_status: str = "none"         # none | hybrid | full_pqc

    # Risk
    hndl_risk: bool = False
    final_algorithm_risk: int = 0

    # Recommended fix
    recommended_algorithm_cert: Optional[str] = None
    recommended_fips_cert: Optional[str] = None
    recommended_algorithm_kex: Optional[str] = None
    recommended_fips_kex: Optional[str] = None
    recommended_next_step: Optional[str] = None

    # Client-side PQC browser compatibility for the detected hybrid scheme
    client_readiness: Optional[dict] = None

    # Scan metadata
    scan_duration_seconds: float = 0.0
    error_message: Optional[str] = None
    pattern_library_version: str = "1.0.0"

    # All algorithm classifications (TLS version + cert + key exchange) for CBOM aggregation
    classifications: list[AlgorithmClassification] = field(default_factory=list)

    # Raw supported TLS versions and all cipher suite names (for CBOM completeness)
    supported_tls_versions: list[str] = field(default_factory=list)
    supported_cipher_suites: list[str] = field(default_factory=list)

    # ---------------------------------------------------------------------------
    # Convenience fields (populated by _process_scan_result)
    # ---------------------------------------------------------------------------

    # "RSA-2048", "ECDSA-P256", etc.  — empty string if cert not parsed
    cert_algorithm: str = ""

    # True if the server certificate is past its notAfter date
    cert_expired: bool = False

    # Aggregate quantum status across all classifications
    # deprecated > vulnerable > hybrid > safe > unknown
    quantum_status: str = "unknown"

    # True if any TLS version or cert algorithm is deprecated
    deprecated: bool = False

    # Threat timeline based on TLS version + cert + HNDL risk
    # immediate | urgent | planned | roadmap
    threat_timeline: str = ""

    # Inferred data shelf life for HNDL assessment (ephemeral|short|medium|long|permanent)
    data_shelf_life: str = ""

    # ---------------------------------------------------------------------------
    # Extended scan metadata (Fix 2 + Fix 4)
    # ---------------------------------------------------------------------------

    # Millisecond-precision duration (derived from scan_duration_seconds)
    scan_duration_ms: int = 0

    # UTC ISO-8601 timestamp of scan start
    scan_timestamp: Optional[str] = None

    # Resolved IP address of the scanned host
    ip_address_scanned: Optional[str] = None

    # True if cert/hostname heuristics indicate a CDN edge node
    cdn_detected: bool = False

    # Detected CDN provider name ("Fastly", "Cloudflare", "Amazon CloudFront", ...)
    cdn_provider: str = ""

    # Confidence in results: "high" | "medium" | "low"
    scan_confidence: str = "high"
    scan_confidence_note: str = ""

    # Outcome category: success | timeout | dns_failure | connection_refused | ssl_error | cdn_blocked | unknown_error
    scan_outcome: str = "success"

    # ---------------------------------------------------------------------------
    # Fix 1 — Estimated HNDL exposure (never a confirmed fact — always inferred)
    # ---------------------------------------------------------------------------

    estimated_hndl_exposure: str = "none"   # high | medium | low | none
    hndl_inference_basis: str = ""

    # ---------------------------------------------------------------------------
    # Fix 2 — PQC Migration Priority (capped at 7.0 for PLANNED timeline)
    # ---------------------------------------------------------------------------

    pqc_migration_priority: float = 0.0

    # ---------------------------------------------------------------------------
    # Fix 3 — Crypto Agility Score
    # ---------------------------------------------------------------------------

    crypto_agility_score: float = 0.0
    crypto_agility_breakdown: dict = field(default_factory=dict)

    # ---------------------------------------------------------------------------
    # Fix 4 — Deployment Readiness Level
    # ---------------------------------------------------------------------------

    deployment_level: int = 1                 # 0=Legacy, 1=Modern Classical, 3=Hybrid, 4=PQC Ready
    deployment_level_name: str = "Modern Classical"

    # ---------------------------------------------------------------------------
    # Origin discovery (CDN-fronted domains — see scanner/origin_discovery.py).
    # A scan of a CDN-fronted domain only sees the edge; these record whether the
    # true origin was assessed and any candidate origin endpoints found via CT logs.
    # ---------------------------------------------------------------------------

    scan_target: str = "direct"            # "direct" | "edge" (CDN) — what was actually scanned
    origin_assessed: bool = False          # True only if the real origin was measured
    origin_discovery_attempted: bool = False
    origin_candidates: list = field(default_factory=list)  # [{"hostname":..., "ip":...}]
    origin_note: str = ""

    # ---------------------------------------------------------------------------
    # Active PQC detection (server-side only — see scanner/pqc_probe.py).
    # Passive sslyze cannot confirm hybrid PQC; these fields record the result of
    # an active OpenSSL 3.5+ handshake probe when enabled.
    # ---------------------------------------------------------------------------

    pqc_active_probed: bool = False        # an active probe was attempted
    pqc_active_supported: bool = False     # server negotiated a hybrid PQC group
    pqc_active_group: str = ""             # e.g. "X25519MLKEM768"
    pqc_active_note: str = ""

    # ---------------------------------------------------------------------------
    # Convenience properties (aliases kept for ergonomic access in tests)
    # ---------------------------------------------------------------------------

    @property
    def key_exchange(self) -> Optional[str]:
        """Alias for key_exchange_algorithm."""
        return self.key_exchange_algorithm

    @property
    def pqc_offered(self) -> bool:
        """True if any PQC cipher (hybrid or pure) is offered."""
        return self.pqc_hybrid_offered or self.pqc_only_offered

    @property
    def algorithm_risk(self) -> int:
        """Alias for final_algorithm_risk."""
        return self.final_algorithm_risk


# ---------------------------------------------------------------------------
# Algorithm extraction helpers
# ---------------------------------------------------------------------------

def _extract_cert_algorithm(cert: x509.Certificate) -> tuple[str, Optional[int]]:
    """Return (algorithm_name, key_size_bits) from a parsed x509 certificate."""
    pub_key = cert.public_key()

    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve_name = pub_key.curve.name.lower()
        curve_map = {
            "secp256r1":  "ECDSA-P256",
            "prime256v1": "ECDSA-P256",
            "secp384r1":  "ECDSA-P384",
            "secp521r1":  "ECDSA-P521",
            "secp256k1":  "ECDSA-secp256k1",
        }
        algo_name = curve_map.get(curve_name, f"ECDSA-{curve_name}")
        return algo_name, pub_key.key_size

    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256

    if isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448", 448

    if isinstance(pub_key, dh.DHPublicKey):
        return "DH", pub_key.key_size

    if isinstance(pub_key, dsa.DSAPublicKey):
        return "DSA", pub_key.key_size

    return "UNKNOWN", None


def _extract_san(cert: x509.Certificate) -> list[str]:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _parse_certificate(leaf_cert: x509.Certificate) -> CertificateInfo:
    algo_name, key_size = _extract_cert_algorithm(leaf_cert)

    expiry = leaf_cert.not_valid_after_utc if hasattr(leaf_cert, "not_valid_after_utc") \
        else leaf_cert.not_valid_after.replace(tzinfo=timezone.utc)

    now = datetime.now(tz=timezone.utc)
    is_expired = expiry < now
    days_until_expiry = (expiry - now).days if not is_expired else -(now - expiry).days

    try:
        issuer_str = leaf_cert.issuer.rfc4514_string()
    except Exception:
        issuer_str = str(leaf_cert.issuer)

    try:
        subject_str = leaf_cert.subject.rfc4514_string()
    except Exception:
        subject_str = str(leaf_cert.subject)

    serial_str = format(leaf_cert.serial_number, "x") if leaf_cert.serial_number >= 0 else "negative"

    return CertificateInfo(
        algorithm=algo_name,
        algorithm_family=algo_name.split("-")[0] if "-" in algo_name else algo_name,
        key_size=key_size,
        expiry_date=expiry,
        issuer=issuer_str,
        subject=subject_str,
        serial=serial_str,
        san=_extract_san(leaf_cert),
        is_expired=is_expired,
        days_until_expiry=days_until_expiry,
    )


def _key_exchange_from_ephemeral_key(
    ephemeral_key,
    cipher_name: str,
) -> str:
    """
    Extract the actual key exchange algorithm from sslyze's ephemeral_key object.

    sslyze negotiates each cipher with the server and records the ephemeral key used:
      - ephemeral_key is None          → static RSA key exchange
      - ephemeral_key.type_name == "DH"   → finite-field Diffie-Hellman (DHE)
      - ephemeral_key.type_name == "ECDH" → elliptic-curve DH; curve in curve_name
        - curve_name == "X25519"       → X25519 (most common in TLS 1.3)
        - curve_name == "secp256r1"    → ECDHE with NIST P-256
        - curve_name == "secp384r1"    → ECDHE with NIST P-384
        - etc.

    TLS 1.3 cipher names (TLS_AES_*, TLS_CHACHA20_*) never encode the key exchange.
    Always use ephemeral_key, not cipher name string matching.
    """
    if ephemeral_key is None:
        return "RSA"

    type_name = getattr(ephemeral_key, "type_name", None) or ""
    curve_name = getattr(ephemeral_key, "curve_name", None) or ""
    ek_size = getattr(ephemeral_key, "size", None)

    if type_name.upper() == "DH":
        if ek_size and ek_size < 2048:
            return "DHE-1024"
        return "DHE"

    if type_name.upper() == "ECDH":
        c = curve_name.lower()
        if c == "x25519":
            return "X25519"
        if c == "x448":
            return "X448"
        if c in ("secp256r1", "prime256v1"):
            return "ECDHE"
        if c == "secp384r1":
            return "ECDHE"
        if c == "secp521r1":
            return "ECDHE"
        if curve_name:
            return f"ECDHE-{curve_name}"
        return "ECDHE"

    # Fallback: try cipher-name heuristic for legacy suites
    return _extract_key_exchange_from_cipher_name(cipher_name)


def _extract_key_exchange_from_cipher_name(cipher_name: str) -> str:
    """
    Fallback: best-effort extraction from OpenSSL cipher name.
    Prefer _key_exchange_from_ephemeral_key when available.

    TLS 1.3 suites (TLS_AES_*, TLS_CHACHA20_*) do NOT encode the key exchange.
    For those, the ephemeral_key approach is the only accurate source.
    """
    name_upper = cipher_name.upper()

    if "KYBER" in name_upper or "MLKEM" in name_upper or "ML_KEM" in name_upper:
        return "ML-KEM (hybrid)" if "X25519" in name_upper else "ML-KEM"

    if "X25519KYBER" in name_upper.replace("_", "").replace("-", ""):
        return "X25519Kyber768"

    if "ECDHE" in name_upper:
        return "ECDHE"
    if "ECDH" in name_upper:
        return "ECDH"
    if "DHE" in name_upper:
        return "DHE"
    if "_DH_" in name_upper:
        return "DH"
    if "_RSA_" in name_upper:
        return "RSA"
    if "PSK" in name_upper:
        return "PSK"

    # TLS 1.3 ciphers — key exchange is NOT in the name; caller must use ephemeral_key
    if name_upper.startswith("TLS_AES") or name_upper.startswith("TLS_CHACHA"):
        return "TLS1.3-HKDF"

    return "UNKNOWN"


def _check_pqc_in_ciphers(cipher_names: list[str]) -> tuple[bool, bool]:
    """
    Returns (pqc_hybrid_offered, pqc_only_offered).
    Checks ALL cipher names from all TLS versions for Kyber/ML-KEM strings.
    Note: real TLS 1.3 cipher names never embed key exchange — use _check_pqc_in_curves too.
    """
    hybrid = False
    pqc_only = False
    for name in cipher_names:
        upper = name.upper().replace("_", "").replace("-", "")
        if "X25519KYBER" in upper or "X25519MLKEM" in upper:
            hybrid = True
        elif "KYBER" in upper or "MLKEM" in upper:
            pqc_only = True
    return hybrid, pqc_only


def _check_pqc_in_curves(curve_names: list[str]) -> tuple[bool, bool]:
    """
    Returns (pqc_hybrid_offered, pqc_only_offered) from supported elliptic curve group names.

    sslyze's ELLIPTIC_CURVES scan returns supported_curves[i].name — servers supporting
    X25519Kyber768 (RFC 9180 / draft-tls-westerbaan) advertise it here, not in cipher names.
    """
    hybrid = False
    pqc_only = False
    for name in curve_names:
        upper = name.upper().replace("_", "").replace("-", "")
        if "X25519KYBER" in upper or "X25519MLKEM" in upper:
            hybrid = True
        elif "KYBER" in upper or "MLKEM" in upper:
            pqc_only = True
    return hybrid, pqc_only


# Browser compatibility matrix for PQC cipher schemes
PQC_CLIENT_SUPPORT: dict[str, dict] = {
    "X25519Kyber768": {
        "chrome": "124+",
        "firefox": "not supported",
        "safari": "not supported",
        "edge": "124+",
        "market_share_supported": 0.65,
        "notes": "Deployed by Google/Cloudflare; Chrome 124+ enabled by default",
    },
    "ML-KEM-768": {
        "chrome": "not supported",
        "firefox": "not supported",
        "safari": "not supported",
        "edge": "not supported",
        "market_share_supported": 0.0,
        "notes": "FIPS 203 standardised Aug 2024; browser support pending",
    },
}


def _detect_hybrid_status(
    cipher_names: list[str],
    curve_names: list[str] | None = None,
) -> str:
    """
    Classify the server's PQC deployment level from cipher list and/or elliptic curve names.

    X25519Kyber768 appears in supported_curves (sslyze ELLIPTIC_CURVES scan), NOT in
    TLS 1.3 cipher names — cipher names never encode the key exchange algorithm.
    """
    has_hybrid = False
    has_pqc_only = False
    for name in list(cipher_names) + list(curve_names or []):
        upper = name.upper().replace("_", "").replace("-", "")
        if "X25519KYBER" in upper or "X25519MLKEM" in upper:
            has_hybrid = True
        elif "KYBER" in upper or "MLKEM" in upper:
            has_pqc_only = True
    if has_pqc_only:
        return "full_pqc"
    if has_hybrid:
        return "hybrid"
    return "none"


def _build_client_readiness(hybrid_status: str) -> Optional[dict]:
    """Return browser compatibility data for the detected PQC scheme."""
    if hybrid_status == "hybrid":
        return PQC_CLIENT_SUPPORT.get("X25519Kyber768")
    if hybrid_status == "full_pqc":
        return PQC_CLIENT_SUPPORT.get("ML-KEM-768")
    return None


def _is_cloud_ip(ip_str: str) -> bool:
    """Return True if ip_str falls in a known AWS/GCP/Azure CIDR range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _CLOUD_NETWORKS)
    except ValueError:
        return False


def _detect_cdn(cert_info: Optional[CertificateInfo]) -> tuple[bool, str]:
    """Heuristic CDN detection from certificate issuer, subject, and SANs.
    Returns (detected, provider_name).
    """
    if cert_info is None:
        return False, ""
    text = " ".join([
        cert_info.issuer.lower(),
        cert_info.subject.lower(),
        " ".join(san.lower() for san in cert_info.san),
    ])
    for ind in _CDN_INDICATORS:
        if ind in text:
            return True, _CDN_DISPLAY.get(ind, ind.title())
    return False, ""


def _compute_scan_confidence(
    cdn_detected: bool,
    scan_duration_ms: int,
    ip_address_scanned: Optional[str],
    cdn_provider: str = "",
) -> tuple[str, str]:
    """Return (confidence, note) based on CDN presence, latency, and IP range."""
    if cdn_detected:
        provider = cdn_provider or "CDN"
        return ("low", f"Edge termination point scanned ({provider}). Origin server config unknown.")
    if scan_duration_ms > 25000:
        return ("low", "Slow response. Possible WAF or load balancer. Results may not reflect origin server.")
    if ip_address_scanned and _is_cloud_ip(ip_address_scanned):
        return ("medium", "Response from cloud provider IP.")
    return ("high", "Direct connection. No CDN detected.")


def _categorize_scan_error(error_trace: Optional[str]) -> str:
    """Map a connectivity error string to a scan_outcome category."""
    if not error_trace:
        return "unknown_error"
    s = str(error_trace).lower()
    s_compact = s.replace(" ", "").replace("_", "")
    if ("hostname could not be resolved" in s
            or "name resolution" in s
            or "no address" in s
            or "couldnotberesolved" in s_compact):
        return "dns_failure"
    if "timed out" in s or "timeout" in s:
        return "timeout"
    if "connection refused" in s or "connection reset" in s:
        return "connection_refused"
    if "ssl" in s or "tls" in s or "certificate" in s or "handshake" in s:
        return "ssl_error"
    return "unknown_error"


def _compute_quantum_status(result: DomainScanResult) -> str:
    """
    Aggregate quantum status across all classifications.
    Precedence: deprecated > vulnerable > hybrid > safe > unknown
    """
    statuses = [c.quantum_status for c in result.classifications]
    if "deprecated" in statuses:
        return "deprecated"
    if result.hybrid_status in ("hybrid",):
        return "hybrid"
    if "vulnerable" in statuses:
        return "vulnerable"
    non_unknown = [s for s in statuses if s != "unknown"]
    if non_unknown and all(s == "safe" for s in non_unknown):
        return "safe"
    return "unknown"


def _compute_threat_timeline(result: DomainScanResult) -> str:
    """
    Classify threat urgency: IMMEDIATE | URGENT | PLANNED | ROADMAP.

    IMMEDIATE — any one condition:
      TLS 1.0/1.1 in use, cert expired, algorithm_risk==10, or deprecated flag.
    URGENT — ALL conditions:
      Static RSA key exchange (TLS_RSA_WITH_* cipher suites) AND long/permanent data.
      X25519 and ECDHE are NOT urgent — only static RSA kex creates HNDL exposure.
    ROADMAP — PQC hybrid/full deployed, or quantum_status safe.
    PLANNED — everything else (modern TLS, quantum-vulnerable but not urgent).
    """
    # IMMEDIATE: any single condition is sufficient
    if (result.tls_version in ("TLS_1_0", "TLS_1_1")
            or result.cert_expired
            or result.final_algorithm_risk == 10
            or result.deprecated):
        return "IMMEDIATE"
    # URGENT: static RSA key exchange + long-lived data → harvest-now-decrypt-later risk
    if (result.key_exchange_algorithm == "RSA"
            and result.data_shelf_life in ("long", "permanent")):
        return "URGENT"
    # ROADMAP: PQC already deployed or quantum-safe algorithm
    if (result.hybrid_status in ("hybrid", "full_pqc")
            or result.quantum_status == "safe"):
        return "ROADMAP"
    # PLANNED: default — modern TLS with quantum-vulnerable algorithms
    return "PLANNED"


def _build_recommended_next_step(
    hybrid_status: str,
    hndl_risk: bool,
    final_algorithm_risk: int,
) -> Optional[str]:
    if hybrid_status == "full_pqc":
        return "Server is PQC-ready. Monitor client support rollout."
    if hybrid_status == "hybrid":
        return (
            "Hybrid PQC deployed (X25519Kyber768). "
            "Plan migration to ML-KEM-only when client support exceeds 80%."
        )
    if hndl_risk:
        return "Deploy X25519Kyber768 hybrid key exchange immediately — HNDL risk detected."
    if final_algorithm_risk >= 7:
        return "Deploy X25519Kyber768 hybrid key exchange to protect against harvest-now attacks."
    return None


def _cert_algorithm_label(cert: CertificateInfo) -> str:
    """Return a canonical label like 'RSA-2048' or 'ECDSA-P256'."""
    if cert.key_size:
        return f"{cert.algorithm}-{cert.key_size}"
    return cert.algorithm


# ---------------------------------------------------------------------------
# Fix 1 — Estimated HNDL exposure helpers
# ---------------------------------------------------------------------------

def _compute_estimated_hndl_exposure(result: "DomainScanResult") -> str:
    """Return estimated HNDL exposure level — always inferred, never confirmed."""
    if result.hndl_risk:
        return "high"
    if (result.quantum_status in ("vulnerable",)
            and result.data_shelf_life in ("medium", "long", "permanent")):
        return "medium"
    if result.quantum_status in ("vulnerable", "deprecated"):
        return "low"
    return "none"


def _compute_hndl_inference_basis(domain: str) -> str:
    """Return a human-readable explanation of why a shelf-life category was inferred."""
    d = domain.lower()
    if any(k in d for k in (
        "pay", "payment", "transaction", "billing", "invoice", "checkout",
        "bank", "banking", "finance", "fintech", "wallet", "loan", "credit",
        "debit", "transfer", "remit", "trading", "invest", "insurance",
        "mortgage", "pension", "tax", "razorpay", "stripe", "paytm",
    )):
        return "financial domain — long-lived data assumed"
    if any(k in d for k in (
        "health", "record", "history", "archive", "medical",
        "hospital", "patient", "clinical", "pharma", "diagnostic", "ehr",
    )):
        return "health domain — long-lived data assumed"
    if any(k in d for k in (
        "auth", "login", "otp", "token", "session", "sso", "oauth", "logout",
    )):
        return "auth domain — ephemeral data assumed"
    return "domain category inference — verify with actual data retention policies"


# ---------------------------------------------------------------------------
# Fix 2 — PQC Migration Priority (caps at 7.0 for PLANNED timeline)
# ---------------------------------------------------------------------------

def _compute_pqc_migration_priority(result: "DomainScanResult") -> float:
    """
    Migration priority score (0–10).
    PLANNED timeline caps at 7.0 — no commercial company on TLS 1.3
    faces active compromise. Only IMMEDIATE/URGENT can exceed 7.0.
    """
    base = float(result.final_algorithm_risk)
    if result.threat_timeline == "PLANNED":
        return min(7.0, base)
    return base


# ---------------------------------------------------------------------------
# Fix 3 — Crypto Agility Score
# ---------------------------------------------------------------------------

def _compute_crypto_agility(
    result: "DomainScanResult",
) -> tuple[float, dict]:
    """
    Score how easily this server can migrate to PQC (0.0–10.0).

    +2.0  TLS 1.3 in use
    +2.0  Forward secrecy (X25519 or ECDHE key exchange)
    +1.0  Certificate not expired
    +0.5  No deprecated protocols
    +2.0  Hybrid PQC detected (X25519Kyber768)
    +2.0  Full PQC cert detected (ML-DSA)
    -2.0  TLS 1.0 or 1.1 in use
    -1.0  Expired certificate
    -1.0  CDN terminated (confidence reduced)
    """
    score = 0.0
    bd: dict = {}

    # TLS 1.3
    if result.tls_version == "TLS_1_3":
        score += 2.0
        bd["tls_1_3"] = {"applied": True, "points": 2.0, "reason": "TLS 1.3 in use"}
    else:
        bd["tls_1_3"] = {"applied": False, "points": 0.0, "reason": "TLS 1.3 not in use"}

    # Legacy TLS penalty
    if result.tls_version in ("TLS_1_0", "TLS_1_1"):
        score -= 2.0
        bd["legacy_tls_penalty"] = {"applied": True, "points": -2.0, "reason": "TLS 1.0/1.1 in use"}
    else:
        bd["legacy_tls_penalty"] = {"applied": False, "points": 0.0, "reason": "No legacy TLS"}

    # Forward secrecy
    kex = result.key_exchange_algorithm or ""
    fs = kex in ("X25519", "X448") or kex.startswith("ECDHE") or kex == "ECDHE"
    if fs:
        score += 2.0
        bd["forward_secrecy"] = {"applied": True, "points": 2.0, "reason": f"Forward secrecy via {kex}"}
    else:
        bd["forward_secrecy"] = {"applied": False, "points": 0.0, "reason": "No forward secrecy detected"}

    # Certificate not expired
    if not result.cert_expired:
        score += 1.0
        bd["cert_valid"] = {"applied": True, "points": 1.0, "reason": "Certificate not expired"}
    else:
        bd["cert_valid"] = {"applied": False, "points": 0.0, "reason": "Certificate expired"}

    # Expired cert penalty
    if result.cert_expired:
        score -= 1.0
        bd["cert_expired_penalty"] = {"applied": True, "points": -1.0, "reason": "Expired certificate"}
    else:
        bd["cert_expired_penalty"] = {"applied": False, "points": 0.0, "reason": ""}

    # No deprecated protocols
    deprecated_versions = {"TLS_1_0", "TLS_1_1", "SSL_2_0", "SSL_3_0"}
    has_deprecated = bool(deprecated_versions & set(result.supported_tls_versions))
    if not has_deprecated:
        score += 0.5
        bd["no_deprecated"] = {"applied": True, "points": 0.5, "reason": "No deprecated TLS protocols"}
    else:
        bd["no_deprecated"] = {"applied": False, "points": 0.0, "reason": "Deprecated protocols present"}

    # Hybrid PQC
    if result.hybrid_status == "hybrid":
        score += 2.0
        bd["hybrid_pqc"] = {"applied": True, "points": 2.0, "reason": "Hybrid PQC (X25519Kyber768) detected"}
    else:
        bd["hybrid_pqc"] = {"applied": False, "points": 0.0, "reason": "No hybrid PQC"}

    # Full PQC cert (ML-DSA)
    cert_algo_upper = (result.cert_algorithm or "").upper()
    if "ML-DSA" in cert_algo_upper or "MLDSA" in cert_algo_upper:
        score += 2.0
        bd["full_pqc_cert"] = {"applied": True, "points": 2.0, "reason": "ML-DSA certificate detected"}
    else:
        bd["full_pqc_cert"] = {"applied": False, "points": 0.0, "reason": "No ML-DSA certificate"}

    # CDN termination penalty
    if result.cdn_detected:
        score -= 1.0
        bd["cdn_penalty"] = {"applied": True, "points": -1.0, "reason": "CDN-terminated — origin config unknown"}
    else:
        bd["cdn_penalty"] = {"applied": False, "points": 0.0, "reason": ""}

    return round(max(0.0, min(10.0, score)), 2), bd


# ---------------------------------------------------------------------------
# Fix 4 — Deployment Readiness Level
# ---------------------------------------------------------------------------

def _compute_deployment_level(result: "DomainScanResult") -> tuple[int, str]:
    """
    Level 0 Legacy           — TLS 1.0/1.1, expired cert, or deprecated
    Level 1 Modern Classical — TLS 1.2/1.3, no PQC (most Indian fintechs)
    Level 3 Hybrid Deployed  — X25519Kyber768 hybrid detected
    Level 4 PQC Ready        — full_pqc + ML-DSA cert
    (Level 2 requires CBOM + migration plan docs, cannot be detected from TLS scan)
    """
    if (result.tls_version in ("TLS_1_0", "TLS_1_1")
            or result.cert_expired
            or result.deprecated):
        return 0, "Legacy"

    cert_upper = (result.cert_algorithm or "").upper()
    if (result.hybrid_status == "full_pqc"
            and ("ML-DSA" in cert_upper or "MLDSA" in cert_upper)):
        return 4, "PQC Ready"

    if result.hybrid_status == "hybrid":
        return 3, "Hybrid Deployed"

    return 1, "Modern Classical"


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class NetworkScanner:
    """
    TLS/certificate scanner for one or more domains.

    Usage:
        scanner = NetworkScanner(timeout=10)
        results = scanner.scan_domains(["api.company.com", "auth.company.com"])
        for result in results:
            print(result.domain, result.quantum_status, result.key_exchange)
    """

    def __init__(
        self,
        timeout: int = 10,
        per_domain_timeout: int = 30,
        max_workers: int = 5,
        rate_limit_seconds: float = 0.5,
        active_pqc: bool = False,
        discover_origin: bool = False,
    ):
        self.timeout = timeout
        self.per_domain_timeout = per_domain_timeout
        self.max_workers = max_workers
        self.rate_limit_seconds = rate_limit_seconds
        # Active PQC probe (server-side only). Adds one extra TLS handshake per
        # domain; requires OpenSSL 3.5+ in the environment (falls back silently).
        self.active_pqc = active_pqc
        # Origin discovery for CDN-fronted domains (CT-log based). Adds a crt.sh
        # lookup + DNS resolves; only runs when the domain is CDN-terminated.
        self.discover_origin = discover_origin

    _USER_AGENT = "SeQr-Scanner/0.1.0 security-research"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan_domains(
        self,
        domains: list[str],
        port: int = 443,
        protocol: str = "https",
    ) -> list[DomainScanResult]:
        """
        Scan domains sequentially with rate limiting between each.

        Args:
            domains:  Hostnames to scan.
            port:     TLS port. Default 443; for STARTTLS protocols the
                      protocol's default port is used unless overridden.
            protocol: "https" (direct TLS) or a STARTTLS/wrapped protocol
                      ("smtp", "imap", "pop3", "postgres").

        Returns:
            List of DomainScanResult, one per input domain.
        """
        if not domains:
            return []
        results = []
        for i, domain in enumerate(domains):
            results.append(self._scan_single_domain(domain, port, protocol))
            if self.rate_limit_seconds > 0 and i < len(domains) - 1:
                time.sleep(self.rate_limit_seconds)
        return results

    def scan_domain(self, domain: str, port: int = 443, protocol: str = "https") -> DomainScanResult:
        """Convenience method to scan a single domain (optionally a STARTTLS protocol)."""
        results = self.scan_domains([domain], port=port, protocol=protocol)
        return results[0] if results else DomainScanResult(
            domain=domain, port=port, reachable=False,
            error_message="No result returned",
        )

    def scan_domains_with_checkpoint(
        self,
        domains: list[str],
        port: int = 443,
        checkpoint_callback=None,
    ) -> list[DomainScanResult]:
        """
        Scan domains with per-result callback and rate limiting.
        Always saves a result even for failed domains — timeout/error are data points.

        Args:
            domains:             Hostnames to scan.
            port:                TLS port, default 443.
            checkpoint_callback: Called with each DomainScanResult after it completes.
        """
        if not domains:
            return []
        results = []
        for i, domain in enumerate(domains):
            result = self._scan_single_domain(domain, port)
            results.append(result)
            if checkpoint_callback is not None:
                checkpoint_callback(result)
            if self.rate_limit_seconds > 0 and i < len(domains) - 1:
                time.sleep(self.rate_limit_seconds)
        return results

    # ------------------------------------------------------------------
    # Internal: per-domain scan
    # ------------------------------------------------------------------

    def _scan_single_domain(self, domain: str, port: int = 443, protocol: str = "https") -> DomainScanResult:
        """
        Scan one domain; returns a DomainScanResult regardless of success or failure.
        Populates scan_timestamp, scan_duration_ms, scan_outcome, ip_address_scanned,
        cdn_detected, scan_confidence, and scan_confidence_note.

        protocol: "https" for direct TLS, or a STARTTLS/wrapped protocol
        ("smtp"/"imap"/"pop3"/"postgres") — the same TLS analysis runs after the
        protocol's opportunistic-TLS upgrade.
        """
        domain = _normalize_domain(domain)
        scan_ts = datetime.now(tz=timezone.utc).isoformat()
        t0 = time.monotonic()

        wrapped = _WRAPPED_PROTOCOLS.get(protocol)
        # For STARTTLS protocols, default to that protocol's port unless the caller
        # passed a non-default one.
        if wrapped and port == 443:
            port = wrapped[1]

        _scan_commands = {
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.ELLIPTIC_CURVES,
        }

        try:
            if wrapped:
                net_cfg = ServerNetworkConfiguration(
                    tls_server_name_indication=domain,
                    tls_opportunistic_encryption=wrapped[0],
                )
                scan_req = ServerScanRequest(
                    server_location=ServerNetworkLocation(domain, port),
                    scan_commands=_scan_commands,
                    network_configuration=net_cfg,
                )
            else:
                scan_req = ServerScanRequest(
                    server_location=ServerNetworkLocation(domain, port),
                    scan_commands=_scan_commands,
                )
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return DomainScanResult(
                domain=domain,
                port=port,
                reachable=False,
                scan_outcome="dns_failure",
                scan_timestamp=scan_ts,
                scan_duration_seconds=elapsed,
                scan_duration_ms=int(elapsed * 1000),
                error_message=f"Invalid hostname: {exc}",
            )

        scanner = Scanner()
        scanner.queue_scans([scan_req])

        for server_scan_result in scanner.get_results():
            elapsed = time.monotonic() - t0

            if server_scan_result.scan_result is None:
                error = str(server_scan_result.connectivity_error_trace or "Unknown error")
                outcome = _categorize_scan_error(error)
                return DomainScanResult(
                    domain=domain,
                    port=port,
                    reachable=False,
                    scan_outcome=outcome,
                    scan_timestamp=scan_ts,
                    scan_duration_seconds=elapsed,
                    scan_duration_ms=int(elapsed * 1000),
                    error_message=error,
                )

            try:
                result = self._process_scan_result(
                    domain, port, server_scan_result.scan_result, elapsed, protocol
                )
                result.scan_timestamp = scan_ts
                result.scan_duration_ms = int(elapsed * 1000)
                result.scan_outcome = "success"

                # Resolved IP from sslyze (validated before storing)
                raw_ip = getattr(server_scan_result.server_location, "ip_address", None)
                if raw_ip:
                    try:
                        ipaddress.ip_address(str(raw_ip))
                        result.ip_address_scanned = str(raw_ip)
                    except ValueError:
                        pass

                # CDN detection: cert text → reverse DNS → CIDR range → HTTP headers
                cdn_by_cert, cdn_name_cert = _detect_cdn(result.cert)
                cdn_name_dns = (
                    _reverse_dns_cdn(result.ip_address_scanned)
                    if result.ip_address_scanned and not cdn_by_cert
                    else ""
                )
                cdn_name_cidr = (
                    _cidr_cdn(result.ip_address_scanned)
                    if result.ip_address_scanned and not cdn_by_cert and not cdn_name_dns
                    else ""
                )
                cdn_name_http = (
                    _http_header_cdn(domain)
                    if not cdn_by_cert and not cdn_name_dns and not cdn_name_cidr
                    else ""
                )
                cdn_provider = cdn_name_cert or cdn_name_dns or cdn_name_cidr or cdn_name_http
                result.cdn_detected = bool(cdn_provider)
                result.cdn_provider = cdn_provider

                conf, note = _compute_scan_confidence(
                    cdn_detected=result.cdn_detected,
                    scan_duration_ms=result.scan_duration_ms,
                    ip_address_scanned=result.ip_address_scanned,
                    cdn_provider=result.cdn_provider,
                )
                result.scan_confidence = conf
                result.scan_confidence_note = note

                # --- Origin discovery (CDN-fronted domains only) ---
                # A CDN-fronted scan measures the EDGE, not the origin. Be explicit
                # about that, and (when enabled) surface candidate origin endpoints.
                if result.cdn_detected:
                    result.scan_target = "edge"
                    result.origin_assessed = False
                    result.origin_note = (
                        f"Edge-terminated ({result.cdn_provider or 'CDN'}). This reflects the "
                        "CDN edge, not the origin server. Assess the origin directly for its true posture."
                    )
                    if self.discover_origin:
                        try:
                            from .origin_discovery import discover_origin_candidates
                            disc = discover_origin_candidates(domain, timeout=float(self.timeout))
                            result.origin_discovery_attempted = disc.queried
                            result.origin_candidates = [
                                {"hostname": c.hostname, "ip": c.ip} for c in disc.candidates
                            ]
                            if disc.candidates:
                                result.origin_note += f" {disc.note}"
                        except Exception as exc:
                            logger.warning("Origin discovery failed for %s: %s", domain, exc)
                else:
                    result.scan_target = "direct"
                    result.origin_assessed = True

                # Fix 1–4: compute after CDN is known (CDN affects agility score)
                result.estimated_hndl_exposure = _compute_estimated_hndl_exposure(result)
                result.hndl_inference_basis = _compute_hndl_inference_basis(domain)
                result.pqc_migration_priority = _compute_pqc_migration_priority(result)
                result.crypto_agility_score, result.crypto_agility_breakdown = _compute_crypto_agility(result)
                result.deployment_level, result.deployment_level_name = _compute_deployment_level(result)

                return result

            except Exception as exc:
                logger.exception("Error processing scan result for %s", domain)
                elapsed = time.monotonic() - t0
                return DomainScanResult(
                    domain=domain,
                    port=port,
                    reachable=True,
                    scan_outcome="unknown_error",
                    scan_timestamp=scan_ts,
                    scan_duration_seconds=elapsed,
                    scan_duration_ms=int(elapsed * 1000),
                    error_message=f"Processing error: {exc}",
                )

        # Scanner returned no results (should not happen)
        elapsed = time.monotonic() - t0
        return DomainScanResult(
            domain=domain,
            port=port,
            reachable=False,
            scan_outcome="unknown_error",
            scan_timestamp=scan_ts,
            scan_duration_seconds=elapsed,
            scan_duration_ms=int(elapsed * 1000),
            error_message="No result returned by scanner",
        )

    # ------------------------------------------------------------------
    # Internal processing
    # ------------------------------------------------------------------

    def _process_scan_result(
        self,
        domain: str,
        port: int,
        scan_result,
        elapsed: float,
        protocol: str = "https",
    ) -> DomainScanResult:
        result = DomainScanResult(
            domain=domain,
            port=port,
            reachable=True,
            scan_duration_seconds=elapsed,
        )

        # --- Collect cipher suites per TLS version ---
        # ordered_versions: best → worst (for picking cipher/kex from best supported version)
        ordered_versions = [
            "TLS_1_3", "TLS_1_2", "TLS_1_1", "TLS_1_0", "SSL_3_0", "SSL_2_0",
        ]
        tls_version_commands = {
            ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL_2_0",
            ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL_3_0",
            ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS_1_0",
            ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS_1_1",
            ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS_1_2",
            ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS_1_3",
        }

        # accepted_suites_by_version: version_label → list of CipherSuiteAcceptedByServer
        accepted_suites_by_version: dict[str, list] = {}
        all_cipher_names: list[str] = []

        for command, version_label in tls_version_commands.items():
            try:
                cmd_result = getattr(scan_result, command.value, None)
                if cmd_result is None:
                    continue
                if hasattr(cmd_result, "result") and cmd_result.result is not None:
                    accepted = cmd_result.result.accepted_cipher_suites
                    if accepted:
                        accepted_suites_by_version[version_label] = list(accepted)
                        all_cipher_names.extend(
                            s.cipher_suite.name for s in accepted
                        )
                        result.supported_tls_versions.append(version_label)
            except Exception as exc:
                logger.debug("Could not read %s for %s: %s", command.value, domain, exc)

        # --- Pick best (highest) supported TLS version ---
        best_tls_version: Optional[str] = None
        for v in ordered_versions:
            if v in result.supported_tls_versions:
                best_tls_version = v
                break

        if best_tls_version:
            result.tls_version = best_tls_version
            result.tls_version_classification = classify_tls_version(best_tls_version)

        result.supported_cipher_suites = list(set(all_cipher_names))

        # --- Elliptic curves (for PQC detection: X25519Kyber768 appears here, not in cipher names) ---
        all_curve_names: list[str] = []
        try:
            ec_cmd = getattr(scan_result, ScanCommand.ELLIPTIC_CURVES.value, None)
            if ec_cmd and hasattr(ec_cmd, "result") and ec_cmd.result is not None:
                for curve in ec_cmd.result.supported_curves:
                    if hasattr(curve, "name"):
                        all_curve_names.append(curve.name)
        except Exception as exc:
            logger.debug("Could not read ELLIPTIC_CURVES for %s: %s", domain, exc)

        # --- Key exchange and cipher suite from best TLS version ---
        best_suites = accepted_suites_by_version.get(best_tls_version or "", [])
        if best_suites:
            first_suite = best_suites[0]
            result.cipher_suite = first_suite.cipher_suite.name

            # Use ephemeral_key for accurate key exchange — never infer from cipher name alone
            ek = getattr(first_suite, "ephemeral_key", None)
            result.key_exchange_algorithm = _key_exchange_from_ephemeral_key(
                ek, first_suite.cipher_suite.name
            )
            if result.key_exchange_algorithm:
                result.key_exchange_classification = classify_algorithm(
                    result.key_exchange_algorithm
                )

        # --- PQC presence: check both cipher names and elliptic curve group names ---
        # TLS 1.3 cipher names (TLS_AES_*, TLS_CHACHA20_*) never encode key exchange;
        # X25519Kyber768 shows up in ELLIPTIC_CURVES.supported_curves, not cipher names.
        cipher_hybrid, cipher_pqc = _check_pqc_in_ciphers(all_cipher_names)
        curve_hybrid, curve_pqc = _check_pqc_in_curves(all_curve_names)
        result.pqc_hybrid_offered = cipher_hybrid or curve_hybrid
        result.pqc_only_offered = cipher_pqc or curve_pqc
        result.hybrid_status = _detect_hybrid_status(all_cipher_names, all_curve_names)
        result.client_readiness = _build_client_readiness(result.hybrid_status)

        # --- Active PQC probe (server-side only) ---
        # Passive detection above can MISS hybrid PQC (sslyze won't send a
        # PQC ClientHello). When enabled, actively confirm via OpenSSL 3.5+ and
        # upgrade the result if the server really negotiates a hybrid PQC group.
        if self.active_pqc:
            try:
                from .pqc_probe import probe_active_pqc
                _wrapped = _WRAPPED_PROTOCOLS.get(protocol)
                _starttls = _wrapped[2] if _wrapped else None
                probe = probe_active_pqc(
                    domain, port, timeout=float(self.timeout), starttls=_starttls
                )
                result.pqc_active_probed = probe.probed
                result.pqc_active_supported = probe.supported
                result.pqc_active_group = probe.negotiated_group
                result.pqc_active_note = probe.note
                if probe.supported:
                    result.pqc_hybrid_offered = True
                    if result.hybrid_status in ("none", "", None):
                        result.hybrid_status = "hybrid"
                        result.client_readiness = _build_client_readiness("hybrid")
            except Exception as exc:  # never let the probe break a scan
                logger.warning("Active PQC probe failed for %s: %s", domain, exc)

        # --- Certificate ---
        try:
            cert_result = getattr(scan_result, ScanCommand.CERTIFICATE_INFO.value, None)
            if cert_result and hasattr(cert_result, "result") and cert_result.result:
                deployments = cert_result.result.certificate_deployments
                if deployments:
                    leaf_cert = deployments[0].received_certificate_chain[0]
                    result.cert = _parse_certificate(leaf_cert)
                    result.cert_algorithm_classification = classify_algorithm(
                        result.cert.algorithm, result.cert.key_size
                    )
                    result.cert_algorithm = _cert_algorithm_label(result.cert)
                    result.cert_expired = result.cert.is_expired
        except Exception as exc:
            logger.warning("Could not parse certificate for %s: %s", domain, exc)

        # --- Data shelf life (used for HNDL threshold) ---
        result.data_shelf_life = infer_shelf_life(domain)

        # --- HNDL risk ---
        # Requires ALL of:
        #   1. quantum-vulnerable key exchange (not just cert signature)
        #   2. data shelf life long or permanent — public web pages (short/medium)
        #      won't persist long enough to be worth harvesting now
        kex_class = result.key_exchange_classification
        if (kex_class
                and kex_class.hndl_candidate
                and kex_class.quantum_status == "vulnerable"
                and result.data_shelf_life in {"long", "permanent"}):
            result.hndl_risk = True

        # --- Final risk score (max across cert + kex + tls version) ---
        risks = []
        if result.cert_algorithm_classification:
            risks.append(result.cert_algorithm_classification.algorithm_risk)
        if result.key_exchange_classification:
            risks.append(result.key_exchange_classification.algorithm_risk)
        if result.tls_version_classification:
            risks.append(result.tls_version_classification.algorithm_risk)
        result.final_algorithm_risk = max(risks) if risks else 0

        # Hybrid PQC deployment lowers effective algorithm risk
        if result.hybrid_status == "full_pqc":
            result.final_algorithm_risk = 0
        elif result.hybrid_status == "hybrid":
            result.final_algorithm_risk = min(result.final_algorithm_risk, 2)

        # --- Recommendations ---
        if result.cert and result.cert_algorithm_classification:
            if result.cert_algorithm_classification.quantum_status in ("vulnerable", "deprecated"):
                rec_algo, rec_fips = recommended_algorithm(result.cert.algorithm)
                result.recommended_algorithm_cert = rec_algo
                result.recommended_fips_cert = rec_fips

        if result.key_exchange_algorithm and result.key_exchange_classification:
            if result.key_exchange_classification.quantum_status in ("vulnerable", "deprecated"):
                rec_algo, rec_fips = recommended_algorithm(result.key_exchange_algorithm)
                result.recommended_algorithm_kex = rec_algo
                result.recommended_fips_kex = rec_fips

        # --- Classifications list for CBOM aggregation ---
        if result.tls_version_classification:
            result.classifications.append(result.tls_version_classification)
        if result.cert_algorithm_classification:
            result.classifications.append(result.cert_algorithm_classification)
        if result.key_exchange_classification:
            result.classifications.append(result.key_exchange_classification)

        # --- Computed aggregate fields ---
        result.quantum_status = _compute_quantum_status(result)
        result.deprecated = result.quantum_status == "deprecated"
        result.threat_timeline = _compute_threat_timeline(result)

        result.recommended_next_step = _build_recommended_next_step(
            result.hybrid_status,
            result.hndl_risk,
            result.final_algorithm_risk,
        )

        return result


# ---------------------------------------------------------------------------
# Async wrapper (used by Celery tasks in audit backend)
# ---------------------------------------------------------------------------

async def scan_domains_async(
    domains: list[str],
    port: int = 443,
    timeout: int = 10,
    per_domain_timeout: int = 30,
    max_workers: int = 5,
) -> list[DomainScanResult]:
    """
    Async wrapper around NetworkScanner. Runs the blocking sslyze scanner
    in a thread pool so it doesn't block the asyncio event loop.
    """
    scanner = NetworkScanner(
        timeout=timeout,
        per_domain_timeout=per_domain_timeout,
        max_workers=max_workers,
    )
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, scanner.scan_domains, domains, port)
