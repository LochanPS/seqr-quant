"""Cloud managed-certificate collector.

Enumerates a cloud provider's managed certificates/keys, read-only. The pilot's first
provider is **AWS ACM** (``provider: aws``): it lists ACM certificates and reads each one's
public metadata — domain, key algorithm, issuer, expiry — via ``ListCertificates`` +
``DescribeCertificate``. ACM never exposes private key material and this collector never
requests any; it is a pure inventory.

Auth model: the standard AWS credential chain (instance role / env / profile) with a
read-only policy (``acm:ListCertificates``, ``acm:DescribeCertificate``). No secret belongs
in the agent config — credentials come from the host's role or environment.

Emits ``cloud_cert`` observations. Additional providers (Azure Key Vault, GCP) slot in behind
the same ``provider`` switch and the same observation shape.

Config:
    provider: aws
    region: ap-south-1
"""

from __future__ import annotations

from ..observation import AssetObservation
from .base import SourcePlugin


class CloudPlugin(SourcePlugin):
    key = "cloud"

    def available(self) -> bool:
        # Injected client (tests / simulation) always runs.
        if callable(self.config.get("_client")):
            return True
        provider = (self.config.get("provider") or "").lower()
        if provider == "aws":
            try:
                import boto3  # noqa: F401
            except Exception:
                return False
            return True
        # Other providers are not wired yet; skip cleanly rather than pretend.
        return False

    def collect(self) -> list[AssetObservation]:
        provider = (self.config.get("provider") or "aws").lower()
        records = self._fetch(provider)
        obs: list[AssetObservation] = []
        for rec in records:
            o = self._normalize(provider, rec)
            if o is not None:
                obs.append(o)
        return obs

    # ---------------------------------------------------------------- fetch
    def _fetch(self, provider: str) -> list[dict]:
        """Return a list of normalized certificate records. A ``_client`` callable in config
        overrides the live provider path (tests + recorded fixtures). Never raises."""
        client = self.config.get("_client")
        if callable(client):
            try:
                return list(client(self.config) or [])
            except Exception:
                return []
        if provider == "aws":
            try:
                return self._fetch_aws()
            except Exception:
                return []
        return []

    def _fetch_aws(self) -> list[dict]:  # pragma: no cover — needs live AWS creds
        import boto3

        acm = boto3.client("acm", region_name=self.config.get("region"))
        out: list[dict] = []
        paginator = acm.get_paginator("list_certificates")
        for page in paginator.paginate():
            for summary in page.get("CertificateSummaryList", []):
                arn = summary.get("CertificateArn")
                if not arn:
                    continue
                try:
                    c = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
                except Exception:
                    continue
                not_after = c.get("NotAfter")
                out.append({
                    "arn": arn,
                    "domain_name": c.get("DomainName"),
                    "key_algorithm": c.get("KeyAlgorithm"),   # e.g. RSA-2048, EC-prime256v1
                    "issuer": c.get("Issuer"),
                    "not_after": not_after.date().isoformat() if hasattr(not_after, "date") else not_after,
                    "in_use": bool(c.get("InUseBy")),
                    "status": c.get("Status"),
                })
        return out

    # ---------------------------------------------------------------- normalize
    def _normalize(self, provider: str, rec: dict) -> AssetObservation | None:
        domain = rec.get("domain_name") or rec.get("arn")
        if not domain:
            return None
        alg, fam, size = _parse_key_algorithm(rec.get("key_algorithm"))
        detail_bits = [f"{provider}:acm"]
        if rec.get("status"):
            detail_bits.append(str(rec["status"]).lower())
        if rec.get("in_use"):
            detail_bits.append("in-use")
        return AssetObservation(
            asset_key=domain, asset_key_type="hostname",
            asset_type="managed_certificate", asset_name=f"{domain} (ACM)",
            location_type="cloud_acm",
            location_detail=" · ".join(detail_bits),
            algorithm=alg, algorithm_family=fam, key_size=size,
            quantum_status="vulnerable",  # RSA / EC managed certs — all classical
            cert_expiry_date=rec.get("not_after"),
            cert_issuer=(rec.get("issuer") or "")[:500] or None,
            confidence="high", plugin=self.key,
        )


def _parse_key_algorithm(key_alg: str | None) -> tuple[str, str | None, int | None]:
    """Map an ACM ``KeyAlgorithm`` (``RSA-2048``, ``EC-prime256v1``, …) to (alg, family, bits)."""
    ka = (key_alg or "").strip()
    up = ka.upper()
    if up.startswith("RSA"):
        digits = "".join(ch for ch in up if ch.isdigit())
        return "RSA", "RSA", int(digits) if digits else None
    if up.startswith("EC"):
        curve_bits = {"PRIME256V1": 256, "SECP256R1": 256, "SECP384R1": 384, "SECP521R1": 521}
        tail = up.split("-", 1)[1] if "-" in up else ""
        return "ECDSA", "ECC", curve_bits.get(tail)
    return (ka or "unknown"), None, None
