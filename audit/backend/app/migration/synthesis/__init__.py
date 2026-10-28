"""Configuration synthesis (PRD 14, Slice 2).

Pure functions that turn an abstract ChangeItem into a deterministic ChangeArtifact — additive
config snippets, instructions, validation checklist, and a rollback. No file mutation, no
execution, no production API calls, no config ownership. Planner decides WHAT; synthesis decides
HOW a platform implements it; the bundle (Slice 3) packages the result.
"""

from app.migration.synthesis.base import ChangeArtifact, synthesize
import app.migration.synthesis.nginx  # noqa: F401 — registers adapter
import app.migration.synthesis.cloudflare  # noqa: F401 — registers adapter


def synthesize_change_item(ci) -> ChangeArtifact:
    """Synthesize an artifact for a persisted ChangeItem."""
    return synthesize(
        provider=ci.provider, action=ci.action, to_state=ci.to_state, from_state=ci.from_state,
        target_component=ci.slot_key, change_item_id=str(ci.id),
    )


def synthesize_plan(db, plan) -> list[ChangeArtifact]:
    """Synthesize artifacts for every ChangeItem in a plan (read-only)."""
    from app.models.migration import ChangeItem

    items = db.query(ChangeItem).filter(ChangeItem.plan_id == plan.id).all()
    return [synthesize_change_item(ci) for ci in items]


__all__ = ["ChangeArtifact", "synthesize", "synthesize_change_item", "synthesize_plan"]
