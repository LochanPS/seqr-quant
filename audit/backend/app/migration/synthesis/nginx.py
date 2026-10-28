"""nginx synthesis adapter (PRD 14, Slice 2). Additive snippets only — never rewrites config."""

from app.migration.synthesis.base import ChangeArtifact, Snippet, _manual, adapter


def _enable_hybrid_kex(to_state, from_state, component) -> ChangeArtifact:
    # to_state may be a concrete group ("X25519MLKEM768") or a prose target from a policy rule
    # ("ephemeral or hybrid KEX"). Only use it verbatim if it looks like a real group token;
    # otherwise fall back to the hybrid default so we never emit an invalid ssl_ecdh_curve value.
    group = to_state if (to_state and " " not in to_state) else "X25519MLKEM768"
    return ChangeArtifact(
        target_platform="nginx", target_component=component or "tls:kex", action="enable_hybrid_kex",
        prerequisites=[
            "nginx linked against OpenSSL >= 3.5 (native ML-KEM groups)",
            "confirm with: nginx -V 2>&1 | grep -o 'OpenSSL[^ ]* [0-9.]*'",
        ],
        required_inputs=["the server{} block for this TLS listener"],
        snippets=[Snippet(
            insertion_point="inside the relevant server{} (or http{}) block, alongside ssl_ directives",
            language="nginx",
            content=f"    # SeQr: offer hybrid post-quantum key exchange, classical fallback preserved\n"
                    f"    ssl_ecdh_curve {group}:X25519:secp256r1;",
        )],
        expected_outcome=f"TLS handshakes negotiate {group} when the client supports it; classical clients unaffected.",
        validation_checklist=[
            "nginx -t   # config test passes",
            "reload: nginx -s reload",
            f"openssl s_client -groups {group} -connect <host>:443 </dev/null | grep -i 'Negotiated'",
            "re-run a SeQr scan; the tls:kex slot should read hybrid",
        ],
        rollback=[
            "remove the added ssl_ecdh_curve line (or restore the previous value from RollbackPlan.pre_state)",
            "nginx -t && nginx -s reload",
        ],
        compatibility="Additive. Classical clients keep working; only adds a hybrid option.",
    )


def _harden_origin(to_state, from_state, component) -> ChangeArtifact:
    return ChangeArtifact(
        target_platform="nginx", target_component=component or "origin", action="harden_origin",
        prerequisites=["the CDN's current edge egress IP ranges", "the CDN origin-pull client CA certificate"],
        required_inputs=["CDN edge IP ranges (allowlist)", "path to the origin-pull CA cert"],
        snippets=[Snippet(
            insertion_point="inside the origin server{} block",
            language="nginx",
            content="    # SeQr: only accept connections proxied by the CDN edge\n"
                    "    ssl_verify_client on;\n"
                    "    ssl_client_certificate /etc/ssl/cdn-origin-pull-ca.pem;\n"
                    "    # allowlist CDN edge ranges; deny direct origin access\n"
                    "    allow <CDN_EDGE_RANGE>;\n"
                    "    deny all;",
        )],
        expected_outcome="Direct-to-origin requests that bypass the CDN edge are refused; the origin bypass is closed.",
        validation_checklist=[
            "nginx -t && nginx -s reload",
            "from outside the CDN ranges: curl https://<origin-ip> --resolve ... should be refused",
            "traffic through the CDN edge continues to succeed",
            "re-run a SeQr scan; the exposed-origin finding should clear",
        ],
        rollback=[
            "set ssl_verify_client off; and remove the allow/deny lines (restore from RollbackPlan.pre_state)",
            "nginx -t && nginx -s reload",
        ],
        compatibility="Potentially disruptive if the allowlist is incomplete — stage on a canary origin first.",
        notes="Pair with the CDN adapter's Authenticated Origin Pulls so the edge presents the client cert.",
    )


def _reissue_cert(to_state, from_state, component) -> ChangeArtifact:
    return ChangeArtifact(
        target_platform="nginx", target_component=component or "tls:cert", action="reissue_cert_stronger",
        prerequisites=["ACME client or CA access to reissue the certificate"],
        required_inputs=["target key type/size (e.g. RSA-3072 or ECDSA P-256)"],
        snippets=[Snippet(
            insertion_point="run where CSRs are generated (not an nginx config change)",
            language="shell",
            content="# SeQr: generate a stronger key + CSR (example: RSA-3072)\n"
                    "openssl req -new -newkey rsa:3072 -nodes -keyout origin-3072.key -out origin-3072.csr",
        )],
        expected_outcome=f"Certificate meets the policy minimum ({to_state or 'RSA-3072+'}). Note: PQC (ML-DSA) certs are a future module.",
        validation_checklist=[
            "openssl x509 -in <new-cert> -noout -text | grep -A1 'Public-Key'",
            "install the reissued cert + reload nginx",
            "re-run a SeQr scan; the tls:cert finding should reflect the stronger key",
        ],
        rollback=["keep the previous certificate/key until the new chain is validated, then switch back if needed"],
        compatibility="Reissue does not change classical trust; public CAs do not yet issue PQC certs.",
    )


@adapter("nginx")
def nginx_adapter(action, to_state, from_state, component) -> ChangeArtifact:
    if action == "enable_hybrid_kex":
        return _enable_hybrid_kex(to_state, from_state, component)
    if action == "enable_forward_secrecy_kex":
        art = _enable_hybrid_kex(to_state or "X25519MLKEM768", from_state, component)
        art.action = "enable_forward_secrecy_kex"
        art.notes = "Static-RSA key exchange has no forward secrecy; move to ephemeral (and hybrid) KEX."
        return art
    if action == "harden_origin":
        return _harden_origin(to_state, from_state, component)
    if action == "reissue_cert_stronger":
        return _reissue_cert(to_state, from_state, component)
    return _manual("nginx", action, component, "nginx adapter has no rule for this action.")
