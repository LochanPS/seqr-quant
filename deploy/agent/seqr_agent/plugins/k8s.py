"""Kubernetes collector — TLS secrets, cert-manager Certificates, and Ingress TLS.

Enumerates the certificates a cluster holds, via the API server, read-only:

  * ``kubernetes.io/tls`` **Secrets** — parses the public ``tls.crt`` leaf only. It NEVER reads
    ``tls.key`` (PRD 15 §8: inventory, not export — private key material is never touched).
  * **cert-manager** ``Certificate`` custom resources (cert-manager.io/v1) — records the
    declared key algorithm/size and DNS names (the issued cert itself lands in a Secret above).
  * **Ingress** ``spec.tls`` — records which hosts terminate TLS and which Secret backs them.

Auth model: the standard kubernetes client credential chain — an in-cluster ServiceAccount
(a read-only Role granting ``get``/``list`` on secrets, ingresses, and cert-manager
certificates) or a kubeconfig. No write verbs are ever issued.

Emits ``k8s_tls_secret`` / ``k8s_cert_manager`` / ``k8s_ingress`` observations.

Config:
    namespaces: []              # empty = all namespaces the credential can list
    include_cert_manager: true
    include_ingress: true
    kubeconfig: null            # null = in-cluster ServiceAccount
"""

from __future__ import annotations

import os

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..observation import AssetObservation
from .base import SourcePlugin

_INCLUSTER_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class K8sPlugin(SourcePlugin):
    key = "k8s"

    def available(self) -> bool:
        # Injected client (tests / air-gap simulation) always runs.
        if callable(self.config.get("_client")):
            return True
        try:
            import kubernetes  # noqa: F401
        except Exception:
            return False
        # Need a way to authenticate: an explicit kubeconfig or an in-cluster ServiceAccount.
        return bool(self.config.get("kubeconfig")) or os.path.isfile(_INCLUSTER_TOKEN)

    def collect(self) -> list[AssetObservation]:
        data = self._gather()
        obs: list[AssetObservation] = []
        seen: set[bytes] = set()

        for sec in data.get("tls_secrets") or []:
            obs.extend(self._from_secret(sec, seen))

        if self.config.get("include_cert_manager", True):
            for cert in data.get("certificates") or []:
                obs.append(self._from_certmanager(cert))

        if self.config.get("include_ingress", True):
            for ing in data.get("ingresses") or []:
                obs.extend(self._from_ingress(ing))

        return [o for o in obs if o is not None]

    # ---------------------------------------------------------------- gather
    def _gather(self) -> dict:
        """Return the normalized cluster snapshot. A ``_client`` callable in config overrides
        the live kubernetes path (tests + recorded fixtures). Never raises."""
        client = self.config.get("_client")
        if callable(client):
            try:
                return dict(client(self.config) or {})
            except Exception:
                return {}
        try:
            return self._gather_live()
        except Exception:
            return {}

    def _gather_live(self) -> dict:  # pragma: no cover — needs a live API server
        import base64

        from kubernetes import client, config as kube_config

        if self.config.get("kubeconfig"):
            kube_config.load_kube_config(config_file=self.config["kubeconfig"])
        else:
            kube_config.load_incluster_config()

        namespaces = self.config.get("namespaces") or []
        core = client.CoreV1Api()
        net = client.NetworkingV1Api()
        custom = client.CustomObjectsApi()

        def _secrets():
            if namespaces:
                for ns in namespaces:
                    yield from core.list_namespaced_secret(ns).items
            else:
                yield from core.list_secret_for_all_namespaces().items

        tls_secrets = []
        for s in _secrets():
            if getattr(s, "type", None) != "kubernetes.io/tls":
                continue
            data = s.data or {}
            crt = data.get("tls.crt")  # public leaf/chain only — tls.key is deliberately ignored
            if not crt:
                continue
            try:
                pem = base64.b64decode(crt)
            except Exception:
                continue
            tls_secrets.append({"namespace": s.metadata.namespace,
                                "name": s.metadata.name, "cert_pem": pem})

        certificates = []
        if self.config.get("include_cert_manager", True):
            try:
                if namespaces:
                    items = []
                    for ns in namespaces:
                        items += custom.list_namespaced_custom_object(
                            "cert-manager.io", "v1", ns, "certificates").get("items", [])
                else:
                    items = custom.list_cluster_custom_object(
                        "cert-manager.io", "v1", "certificates").get("items", [])
            except Exception:
                items = []
            for c in items:
                spec = c.get("spec", {}) or {}
                pk = spec.get("privateKey", {}) or {}
                certificates.append({
                    "namespace": c.get("metadata", {}).get("namespace"),
                    "name": c.get("metadata", {}).get("name"),
                    "dns_names": spec.get("dnsNames") or ([spec.get("commonName")] if spec.get("commonName") else []),
                    "key_algorithm": pk.get("algorithm"),  # RSA | ECDSA | Ed25519
                    "key_size": pk.get("size"),
                })

        ingresses = []
        if self.config.get("include_ingress", True):
            def _ings():
                if namespaces:
                    for ns in namespaces:
                        yield from net.list_namespaced_ingress(ns).items
                else:
                    yield from net.list_ingress_for_all_namespaces().items
            for ing in _ings():
                for t in (getattr(ing.spec, "tls", None) or []):
                    ingresses.append({
                        "namespace": ing.metadata.namespace, "name": ing.metadata.name,
                        "hosts": list(getattr(t, "hosts", None) or []),
                        "secret_name": getattr(t, "secret_name", None),
                    })

        return {"tls_secrets": tls_secrets, "certificates": certificates, "ingresses": ingresses}

    # ---------------------------------------------------------------- normalize
    def _from_secret(self, sec: dict, seen: set) -> list[AssetObservation]:
        pem = sec.get("cert_pem")
        if isinstance(pem, str):
            pem = pem.encode()
        ns, name = sec.get("namespace", "default"), sec.get("name", "tls")
        out: list[AssetObservation] = []
        for der in _leaf_ders(pem or b""):
            if der in seen:
                continue
            seen.add(der)
            fields = _cert_fields(der)
            if fields is None:
                continue
            alg, fam, size, issuer, expiry = fields
            out.append(AssetObservation(
                asset_key=f"k8s:{ns}/{name}", asset_key_type="k8s_secret",
                asset_type="k8s_tls_secret", asset_name=f"{ns}/{name}",
                location_type="k8s_tls_secret",
                location_detail=f"Secret {ns}/{name} (kubernetes.io/tls)",
                algorithm=alg, algorithm_family=fam, key_size=size,
                cert_expiry_date=expiry, cert_issuer=issuer, confidence="high",
                plugin=self.key,
            ))
            break  # the leaf is the first cert; chain intermediates aren't the asset's key
        return out

    def _from_certmanager(self, cert: dict) -> AssetObservation:
        ns, name = cert.get("namespace", "default"), cert.get("name", "cert")
        alg = (cert.get("key_algorithm") or "RSA")
        fam = {"rsa": "RSA", "ecdsa": "ECC", "ed25519": "ECC"}.get(alg.lower(), None)
        dns = ", ".join(cert.get("dns_names") or [])
        return AssetObservation(
            asset_key=f"k8s-cert:{ns}/{name}", asset_key_type="k8s_certificate",
            asset_type="k8s_cert_manager", asset_name=f"{ns}/{name}",
            location_type="k8s_cert_manager",
            location_detail=f"cert-manager Certificate {ns}/{name}" + (f" · {dns}" if dns else ""),
            algorithm=alg, algorithm_family=fam, key_size=cert.get("key_size"),
            quantum_status="vulnerable",  # RSA/ECDSA/Ed25519 issuance — all classical
            confidence="medium",          # declared in spec, not an observed cert
            plugin=self.key,
        )

    def _from_ingress(self, ing: dict) -> list[AssetObservation]:
        ns, name = ing.get("namespace", "default"), ing.get("name", "ingress")
        secret = ing.get("secret_name")
        hosts = ing.get("hosts") or []
        key_host = hosts[0] if hosts else f"{ns}/{name}"
        return [AssetObservation(
            asset_key=f"k8s-ingress:{ns}/{name}", asset_key_type="hostname",
            asset_type="k8s_ingress", asset_name=f"{ns}/{name}",
            location_type="k8s_ingress",
            location_detail=f"Ingress {ns}/{name} · hosts: {', '.join(hosts) or '—'}"
                            + (f" · secret: {secret}" if secret else ""),
            algorithm="tls-terminated", algorithm_family=None,
            quantum_status="unknown",  # the crypto lives in the referenced Secret (covered above)
            confidence="low", plugin=self.key,
        )]


# ---------------------------------------------------------------- cert helpers
def _leaf_ders(pem_or_der: bytes) -> list[bytes]:
    """DER bytes of every certificate in a PEM bundle (leaf first) or a single DER."""
    if not pem_or_der:
        return []
    ders: list[bytes] = []
    if b"-----BEGIN CERTIFICATE-----" in pem_or_der:
        try:
            from cryptography.hazmat.primitives.serialization import Encoding
            for c in x509.load_pem_x509_certificates(pem_or_der):
                ders.append(c.public_bytes(Encoding.DER))
        except Exception:
            try:
                from cryptography.hazmat.primitives.serialization import Encoding
                ders.append(x509.load_pem_x509_certificate(pem_or_der).public_bytes(Encoding.DER))
            except Exception:
                pass
    else:
        ders.append(pem_or_der)
    return ders


def _cert_fields(der: bytes):
    """(algorithm, family, key_size, issuer, expiry) for a DER cert, or None if unparseable."""
    try:
        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
    except Exception:
        return None
    if isinstance(pub, rsa.RSAPublicKey):
        alg, fam, size = "RSA", "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        alg, fam, size = "ECDSA", "ECC", pub.curve.key_size
    else:
        alg, fam, size = type(pub).__name__, "OTHER", None
    try:
        issuer = cert.issuer.rfc4514_string()[:500] or None
    except Exception:
        issuer = None
    try:
        expiry = cert.not_valid_after_utc.date().isoformat()
    except Exception:
        try:
            expiry = cert.not_valid_after.date().isoformat()
        except Exception:
            expiry = None
    return alg, fam, size, issuer, expiry
