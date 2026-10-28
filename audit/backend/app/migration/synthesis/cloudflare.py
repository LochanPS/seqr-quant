"""Cloudflare synthesis adapter (PRD 14, Slice 2).

Honest by design: Cloudflare enables hybrid post-quantum key exchange at its edge BY DEFAULT —
there is no customer knob to "turn on" X25519MLKEM768 there. So a kex finding on a Cloudflare
asset is really about the ORIGIN, and the adapter says so instead of inventing a fake toggle.
The real Cloudflare remediation surface is Authenticated Origin Pulls (mTLS) + restricting the
origin to Cloudflare IPs. Instructions only — never calls the Cloudflare API.
"""

from app.migration.synthesis.base import ChangeArtifact, Snippet, _manual, adapter


def _edge_already_hybrid(to_state, from_state, component) -> ChangeArtifact:
    return ChangeArtifact(
        target_platform="cloudflare", target_component=component or "tls:kex", action="no_action_edge_already_hybrid",
        expected_outcome="No edge change needed — Cloudflare already negotiates hybrid PQC key exchange at the edge.",
        validation_checklist=[
            "confirm the client<->edge handshake negotiates a hybrid group (SeQr active probe already shows this)",
        ],
        compatibility="Informational.",
        notes="The measured gap is NOT the edge. It is the exposed classical origin behind Cloudflare — "
              "remediate with harden_origin (Authenticated Origin Pulls + origin IP allowlist).",
    )


def _harden_origin(to_state, from_state, component) -> ChangeArtifact:
    return ChangeArtifact(
        target_platform="cloudflare", target_component=component or "origin", action="harden_origin",
        prerequisites=[
            "Cloudflare zone with the origin proxied (orange-cloud)",
            "ability to edit origin firewall / security group rules",
        ],
        required_inputs=["Cloudflare zone name", "origin host firewall control"],
        snippets=[Snippet(
            insertion_point="Cloudflare dashboard / manual steps (SeQr does not call the API)",
            language="text",
            content="1. SSL/TLS -> Origin Server -> enable 'Authenticated Origin Pulls' (zone-level mTLS).\n"
                    "2. Install the Cloudflare origin-pull CA on the origin and require the client cert\n"
                    "   (see the paired nginx harden_origin snippet: ssl_verify_client on).\n"
                    "3. Restrict the origin firewall to Cloudflare's published IP ranges; deny all other inbound 443.\n"
                    "   Optionally replace public exposure with a Cloudflare Tunnel (no inbound origin port).",
        )],
        expected_outcome="Only Cloudflare's edge can reach the origin; direct-to-origin bypass is closed.",
        validation_checklist=[
            "from a non-Cloudflare host, a direct request to the origin IP is refused",
            "requests through the Cloudflare edge still succeed",
            "re-run a SeQr scan; the exposed-origin finding should clear",
        ],
        rollback=[
            "disable Authenticated Origin Pulls in the dashboard",
            "restore the previous origin firewall rules (from RollbackPlan.pre_state)",
        ],
        compatibility="Disruptive if the origin firewall allowlist is incomplete — stage carefully.",
    )


@adapter("cloudflare")
def cloudflare_adapter(action, to_state, from_state, component) -> ChangeArtifact:
    if action in ("enable_hybrid_kex", "enable_forward_secrecy_kex"):
        return _edge_already_hybrid(to_state, from_state, component)
    if action == "harden_origin":
        return _harden_origin(to_state, from_state, component)
    if action == "reissue_cert_stronger":
        art = ChangeArtifact(
            target_platform="cloudflare", target_component=component or "tls:cert", action="reissue_cert_stronger",
            expected_outcome="Cloudflare manages the EDGE certificate; strengthen the ORIGIN cert on the origin host.",
            notes="Edge cert is Cloudflare-managed. For the origin, follow the nginx reissue_cert_stronger steps or "
                  "use a Cloudflare Origin CA certificate.",
            compatibility="Informational.",
        )
        return art
    return _manual("cloudflare", action, component, "cloudflare adapter has no rule for this action.")
