"""
Context-aware risk engine (v2) for SeQr findings.

v1 (``risk.py``) scores a finding from its algorithm, data sensitivity and shelf life. For code
findings every context input falls back to a default, so every RSA hit comes out identical — 18
findings, 18 × HIGH. A CISO cannot act on that.

v2 asks *where the crypto lives and what it protects*, and ranks findings by real risk:

    score = base(algorithm) × role × exposure × data × [HNDL] × code_reality × blast × controls

Every factor that moves the score carries a written reason, so the ranking is explainable.
Context is inferred from the file path (relative to the scan root) and can be overridden per
glob with a JSON/YAML context file — inferred values are reported as such, never asserted.

HNDL exposure is an estimated, predictive metric based on data-type endurance, not an indicator
of active interception or a confirmed breach.

Stdlib only, so the CLI can vendor it unchanged. v1 is left untouched.
"""

from __future__ import annotations

import fnmatch
import json
import math
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Optional

HNDL_DISCLAIMER = (
    "HNDL exposure scores are predictive cryptographic risk metrics based on data-type "
    "endurance, not indicators of active data interception or confirmed network breaches."
)

# ── factor tables ─────────────────────────────────────────────────────────────

ROLE_WEIGHT: dict[str, float] = {
    "key_exchange": 1.0,
    "encryption": 1.0,
    "keygen": 0.85,
    "signature": 0.65,
    "hash": 0.3,
    "unknown": 0.8,
}
ROLE_REASON: dict[str, str] = {
    "key_exchange": "key exchange — traffic captured today can be decrypted once a quantum computer exists",
    "encryption": "public-key encryption — ciphertext captured today can be decrypted later",
    "keygen": "key generated here — its use (encrypt vs sign) is not visible at this line",
    "signature": "signature — forgery needs a quantum computer at signing time; not retroactive",
    "hash": "hash — Grover only halves the margin; low quantum priority",
    "unknown": "crypto role not determined from the code",
}

EXPOSURE_WEIGHT: dict[str, float] = {
    "internet": 1.0,
    "at_rest": 0.7,
    "internal": 0.6,
    "offline": 0.35,
    "unknown": 0.75,
}
EXPOSURE_REASON: dict[str, str] = {
    "internet": "internet-facing — reachable by any attacker",
    "at_rest": "protects data at rest — needs a prior breach, but leaked backups stay decryptable",
    "internal": "internal service — attacker needs a foothold inside the network first",
    "offline": "offline / batch use — little remote attack surface",
    "unknown": "exposure unknown — supply a context file to refine",
}

SENSITIVITY_SCORE: dict[str, int] = {
    "highly_confidential": 10, "confidential": 8, "internal": 5, "public": 1,
}
SHELF_LIFE_MULT: dict[str, float] = {
    "ephemeral": 0.2, "short": 0.5, "medium": 1.0, "long": 1.5, "permanent": 2.0,
}

CODE_REALITY_WEIGHT: dict[str, float] = {
    "production": 1.0, "vendored": 0.7, "example": 0.3, "test": 0.15,
}
CODE_REALITY_REASON: dict[str, str] = {
    "vendored": "vendored / third-party code — fix via an upstream upgrade",
    "example": "example or sample code — usually not deployed",
    "test": "test code — not part of the deployed system",
}

HNDL_BOOST = 1.2
SHARED_BOOST = 1.15
CONTROL_FACTOR = 0.85
CONTROL_FLOOR = 0.6
LOW_CONFIDENCE_FACTOR = 0.85

TIERS: tuple[tuple[float, str], ...] = (
    (70.0, "IMMEDIATE"), (45.0, "URGENT"), (20.0, "PLANNED"), (0.0, "MONITOR"),
)

# ── path heuristics (relative to the scan root) ───────────────────────────────

_INTERNET_PARTS = {"gateway", "web", "api", "public", "frontend", "edge", "ingress", "www", "http", "routes"}
_AT_REST_PARTS = {"db", "database", "storage", "backup", "backups", "vault", "archive", "kms", "keystore"}
_INTERNAL_PARTS = {"infra", "internal", "worker", "workers", "batch", "admin", "ops", "deploy", "jobs", "cron"}
_OFFLINE_PARTS = {"scripts", "tools", "migrations"}

_HIGH_PERSISTENCE = {"auth", "login", "kyc", "profile", "account", "accounts", "user", "users",
                     "health", "archive", "vault", "backup", "export", "history", "payments",
                     "payment", "card", "cards", "ledger", "statements", "loans"}
_LOW_PERSISTENCE = {"ticker", "heartbeat", "static", "public", "images", "metrics", "assets"}
_SHARED_PARTS = {"shared", "common", "lib", "libs", "core", "gateway", "sdk"}

_TEST_PARTS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata"}
_EXAMPLE_PARTS = {"example", "examples", "sample", "samples", "demo", "demos"}
_VENDOR_PARTS = {"vendor", "node_modules", "third_party", "thirdparty", "site-packages"}


def _parts(rel: PurePosixPath) -> list[str]:
    return [p.lower() for p in rel.parts]


def _infer_code_reality(rel: PurePosixPath) -> str:
    parts = _parts(rel)
    name = parts[-1] if parts else ""
    dirs = set(parts[:-1])
    if dirs & _VENDOR_PARTS:
        return "vendored"
    if (dirs & _TEST_PARTS or name.startswith("test_") or "_test." in name
            or ".test." in name or ".spec." in name):
        return "test"
    if dirs & _EXAMPLE_PARTS:
        return "example"
    return "production"


def _infer_exposure(rel: PurePosixPath) -> str:
    dirs = set(_parts(rel)[:-1]) | {Path(rel.name).stem.lower()}
    tokens = set()
    for d in dirs:
        tokens.update(d.replace("-", "_").split("_"))
    if tokens & _INTERNET_PARTS:
        return "internet"
    if tokens & _AT_REST_PARTS:
        return "at_rest"
    if tokens & _INTERNAL_PARTS:
        return "internal"
    if tokens & _OFFLINE_PARTS:
        return "offline"
    return "unknown"


def _infer_data(rel: PurePosixPath) -> tuple[str, str]:
    tokens = set()
    for p in _parts(rel):
        tokens.update(Path(p).stem.replace("-", "_").split("_"))
    if tokens & _HIGH_PERSISTENCE:
        return "confidential", "long"
    if tokens & _LOW_PERSISTENCE:
        return "public", "short"
    return "internal", "medium"


def _is_shared(rel: PurePosixPath) -> bool:
    return bool(set(_parts(rel)[:-1]) & _SHARED_PARTS)


def infer_role(finding: Any) -> str:
    """Crypto role from the finding's algorithm + the code it matched."""
    fam = (getattr(finding, "algorithm_family", "") or "").upper()
    alg = (getattr(finding, "algorithm", "") or "").upper()
    text = " ".join(str(getattr(finding, a, "") or "") for a in
                    ("code_snippet", "matched_function", "matched_string", "matched_import")).lower()

    if fam in {"SHA", "MD5", "HASH"} or alg.startswith(("SHA", "MD5")):
        return "hash"
    if fam in {"DH", "ECDH", "KEM"} or any(k in alg for k in ("ECDH", "X25519", "X448", "DH")) \
            or any(k in text for k in ("diffie", "exchange(", "ecdh", "derive", "generate_parameters")):
        return "key_exchange"
    if any(k in text for k in ("encrypt", "oaep", "cipher", "wrap_key", "seal")):
        return "encryption"
    if "ECDSA" in alg or "DSA" in alg or any(k in alg for k in ("SHA256", "RS256", "ES256", "PS256")) \
            or any(k in text for k in ("sign", "verify", "jwt", "rs256", "es256", "signature")):
        return "signature"
    if any(k in text for k in ("generate", "keypair", "key_pair", "keygen", "initialize")):
        return "keygen"
    return "unknown"


# ── context file ──────────────────────────────────────────────────────────────

_CONTEXT_KEYS = {"exposure", "data_sensitivity", "shelf_life", "code_reality", "dependents", "controls", "role"}


@dataclass
class RiskContext:
    """Per-glob overrides. Later matching rules override earlier ones, field by field."""

    rules: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None) -> "RiskContext":
        if not path:
            return cls()
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() in {".yml", ".yaml"}:
            try:
                import yaml  # optional
            except ImportError as e:  # pragma: no cover
                raise ValueError("YAML context needs PyYAML; use a .json context file") from e
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        rules = data.get("rules", []) if isinstance(data, dict) else []
        for r in rules:
            if "match" not in r:
                raise ValueError(f"context rule missing 'match': {r}")
            unknown = set(r) - _CONTEXT_KEYS - {"match", "note"}
            if unknown:
                raise ValueError(f"unknown context keys {sorted(unknown)} in rule {r['match']}")
        return cls(rules=rules)

    def resolve(self, rel: PurePosixPath) -> dict:
        out: dict = {}
        s = rel.as_posix()
        for r in self.rules:
            if fnmatch.fnmatch(s, r["match"]) or fnmatch.fnmatch(s, r["match"].rstrip("/") + "/*"):
                out.update({k: v for k, v in r.items() if k in _CONTEXT_KEYS})
        return out


# ── assessment ────────────────────────────────────────────────────────────────

@dataclass
class Factor:
    name: str
    multiplier: float
    reason: str


@dataclass
class RiskAssessment:
    file_path: str
    rel_path: str
    line_number: int
    algorithm: str
    algorithm_family: str
    score: float
    tier: str
    role: str
    exposure: str
    data_sensitivity: str
    shelf_life: str
    code_reality: str
    dependents: int
    controls: list[str]
    hndl: bool
    factors: list[Factor]
    inferred: list[str]          # which context fields came from path heuristics
    recommended_replacement: str = ""
    duplicates: int = 0          # other matches collapsed into this one (same file/line/family)

    def reasons(self, n: int = 2) -> list[str]:
        """The n factors that moved the score most (either direction), strongest first."""
        movers = sorted(self.factors[1:], key=lambda f: abs(math.log(f.multiplier)) if f.multiplier > 0 else 9,
                        reverse=True)
        return [f.reason for f in movers[:n]] or [self.factors[0].reason]

    @property
    def top_reason(self) -> str:
        return self.reasons(1)[0]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["factors"] = [f.__dict__ for f in self.factors]
        d["top_reason"] = self.top_reason
        return d


def tier_for(score: float) -> str:
    for threshold, name in TIERS:
        if score >= threshold:
            return name
    return "MONITOR"


def _rel(file_path: str, root: str | Path | None) -> PurePosixPath:
    p = Path(file_path)
    if root:
        try:
            return PurePosixPath(p.resolve().relative_to(Path(root).resolve()).as_posix())
        except ValueError:
            pass
    return PurePosixPath(p.as_posix())


def assess_finding(finding: Any, root: str | Path | None = None,
                   context: Optional[RiskContext] = None) -> RiskAssessment:
    rel = _rel(getattr(finding, "file_path", ""), root)
    ctx = (context or RiskContext()).resolve(rel)
    inferred: list[str] = []

    def pick(key: str, infer):
        if key in ctx:
            return ctx[key]
        inferred.append(key)
        return infer()

    role = pick("role", lambda: infer_role(finding))
    exposure = pick("exposure", lambda: _infer_exposure(rel))
    data = _infer_data(rel)
    sensitivity = pick("data_sensitivity", lambda: data[0])
    shelf = pick("shelf_life", lambda: data[1])
    reality = pick("code_reality", lambda: _infer_code_reality(rel))
    dependents = int(ctx.get("dependents", 1) or 1)
    controls = list(ctx.get("controls", []) or [])

    algo_risk = int(getattr(finding, "algorithm_risk", 0) or 0)
    status = (getattr(finding, "quantum_status", "vulnerable") or "vulnerable").lower()
    base = 0.0 if status == "safe" else float(algo_risk * 10)
    factors = [Factor("algorithm", base,
                      f"{getattr(finding, 'algorithm', '?')} — algorithm risk {algo_risk}/10"
                      + (" (post-quantum safe)" if status == "safe" else ""))]

    factors.append(Factor("role", ROLE_WEIGHT.get(role, 0.8), ROLE_REASON.get(role, role)))
    factors.append(Factor("exposure", EXPOSURE_WEIGHT.get(exposure, 0.75), EXPOSURE_REASON.get(exposure, exposure)))

    s = SENSITIVITY_SCORE.get(sensitivity, 5)
    m = SHELF_LIFE_MULT.get(shelf, 1.0)
    data_factor = round(0.55 + 0.45 * (s / 10) * (min(m, 1.5) / 1.5), 3)
    factors.append(Factor("data", data_factor, f"{sensitivity} data, {shelf} shelf life"))

    # Only when confidentiality use is visible in the code — a bare keygen may just sign.
    hndl = (role in {"key_exchange", "encryption"} and exposure in {"internet", "at_rest"}
            and shelf in {"long", "permanent"} and status != "safe")
    if hndl:
        factors.append(Factor("hndl", HNDL_BOOST,
                              "estimated harvest-now-decrypt-later exposure: long-lived data on a reachable channel"))

    if reality != "production":
        factors.append(Factor("code_reality", CODE_REALITY_WEIGHT.get(reality, 1.0),
                              CODE_REALITY_REASON.get(reality, reality)))

    blast = 1.0
    if _is_shared(rel):
        blast *= SHARED_BOOST
    if dependents > 1:
        blast *= 1 + 0.15 * math.log2(dependents)
    blast = min(round(blast, 3), 1.5)
    if blast > 1.0:
        why = [w for w, ok in (("shared module", _is_shared(rel)), (f"{dependents} dependents", dependents > 1)) if ok]
        factors.append(Factor("blast_radius", blast, "wide blast radius — " + ", ".join(why)))

    if controls:
        c = max(CONTROL_FLOOR, CONTROL_FACTOR ** len(controls))
        factors.append(Factor("controls", round(c, 3), "compensating controls: " + ", ".join(controls)))

    if (getattr(finding, "confidence", "high") or "high").lower() == "low":
        factors.append(Factor("confidence", LOW_CONFIDENCE_FACTOR, "low-confidence pattern match"))

    score = base
    for f in factors[1:]:
        score *= f.multiplier
    score = round(min(100.0, score), 1)

    return RiskAssessment(
        file_path=getattr(finding, "file_path", ""), rel_path=rel.as_posix(),
        line_number=int(getattr(finding, "line_number", 0) or 0),
        algorithm=getattr(finding, "algorithm", ""), algorithm_family=getattr(finding, "algorithm_family", ""),
        score=score, tier=tier_for(score), role=role, exposure=exposure,
        data_sensitivity=sensitivity, shelf_life=shelf, code_reality=reality,
        dependents=dependents, controls=controls, hndl=hndl, factors=factors, inferred=inferred,
        recommended_replacement=getattr(finding, "recommended_replacement", "") or "",
    )


def assess_findings(findings: Iterable[Any], root: str | Path | None = None,
                    context: Optional[RiskContext] = None) -> list[RiskAssessment]:
    """Assess, collapse duplicate matches (same file/line/family), and rank highest risk first."""
    best: dict[tuple, RiskAssessment] = {}
    for f in findings:
        a = assess_finding(f, root, context)
        key = (a.rel_path, a.line_number, a.algorithm_family)
        if key in best:
            keep = max(best[key], a, key=lambda x: x.score)
            keep.duplicates = best[key].duplicates + 1
            best[key] = keep
        else:
            best[key] = a
    return sorted(best.values(), key=lambda a: (-a.score, a.rel_path, a.line_number))


def summarize(assessments: list[RiskAssessment]) -> dict:
    tiers = {name: 0 for _, name in TIERS}
    for a in assessments:
        tiers[a.tier] += 1
    return {
        "findings": len(assessments),
        "tiers": tiers,
        "hndl": sum(1 for a in assessments if a.hndl),
        "inferred_exposure": sum(1 for a in assessments if "exposure" in a.inferred),
        "hndl_disclaimer": HNDL_DISCLAIMER,
    }
