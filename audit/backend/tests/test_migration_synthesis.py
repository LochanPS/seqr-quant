"""Configuration synthesis adapters (PRD 14, Slice 2)."""

import os
import uuid
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from app.migration.synthesis import synthesize, synthesize_change_item


def test_nginx_enable_hybrid_kex_is_additive_and_reversible():
    art = synthesize("nginx", "enable_hybrid_kex", to_state="X25519MLKEM768", target_component="tls:kex")
    assert art.target_platform == "nginx"
    assert any("X25519MLKEM768" in sn.content for sn in art.snippets)
    assert all(sn.additive for sn in art.snippets)
    assert any("OpenSSL >= 3.5" in p for p in art.prerequisites)
    assert art.rollback and art.validation_checklist


def test_cloudflare_kex_is_honest_no_fake_toggle():
    art = synthesize("cloudflare", "enable_hybrid_kex", target_component="tls:kex")
    # Cloudflare edge is already hybrid — must NOT invent a toggle; must redirect to the origin.
    assert art.action == "no_action_edge_already_hybrid"
    assert art.snippets == []
    assert "origin" in (art.notes or "").lower()


def test_cloudflare_harden_origin_uses_authenticated_origin_pulls():
    art = synthesize("cloudflare", "harden_origin", target_component="origin")
    blob = " ".join(sn.content for sn in art.snippets).lower()
    assert "authenticated origin pulls" in blob
    assert art.rollback


def test_nginx_harden_origin_enforces_mtls_and_allowlist():
    art = synthesize("nginx", "harden_origin")
    blob = " ".join(sn.content for sn in art.snippets)
    assert "ssl_verify_client on" in blob and "deny all" in blob


def test_unknown_provider_falls_back_to_manual_review():
    art = synthesize("f5", "enable_hybrid_kex")
    assert art.action == "manual_review"


def test_synthesis_is_deterministic():
    a = synthesize("nginx", "enable_hybrid_kex", to_state="X25519MLKEM768")
    b = synthesize("nginx", "enable_hybrid_kex", to_state="X25519MLKEM768")
    assert a.model_dump() == b.model_dump()


def test_synthesize_change_item_wraps_orm_object():
    ci = SimpleNamespace(provider="nginx", action="reissue_cert_stronger", to_state="RSA-3072",
                         from_state="RSA-2048", slot_key="tls:cert", id=uuid.uuid4())
    art = synthesize_change_item(ci)
    assert art.change_item_id == str(ci.id)
    assert art.action == "reissue_cert_stronger"
