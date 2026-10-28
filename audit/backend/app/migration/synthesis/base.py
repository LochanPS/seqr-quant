"""Synthesis artifact type + adapter registry (PRD 14, Slice 2)."""

from typing import Callable, Optional

from pydantic import BaseModel, Field


class Snippet(BaseModel):
    insertion_point: str        # where it goes, e.g. "server { ... } block" — never a full file
    language: str               # nginx | text | shell
    content: str
    additive: bool = True       # snippets only ADD; they never rewrite existing config


class ChangeArtifact(BaseModel):
    """Deterministic output for one ChangeItem. Pure function of the item — no timestamps/random."""

    change_item_id: Optional[str] = None
    target_platform: str
    target_component: Optional[str] = None   # slot_key, e.g. "tls:kex"
    action: str
    required_inputs: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    snippets: list[Snippet] = Field(default_factory=list)
    expected_outcome: str = ""
    validation_checklist: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    compatibility: str = ""
    notes: Optional[str] = None


# provider -> adapter fn(action, to_state, from_state, target_component) -> ChangeArtifact
_ADAPTERS: dict[str, Callable] = {}


def adapter(provider: str):
    def _register(fn: Callable) -> Callable:
        _ADAPTERS[provider] = fn
        return fn
    return _register


def _manual(provider: str, action: str, target_component, note: str) -> ChangeArtifact:
    return ChangeArtifact(
        target_platform=provider, target_component=target_component, action="manual_review",
        expected_outcome="A human must map this change for the target platform.",
        notes=f"{note} (requested action: {action})",
    )


def synthesize(provider: str, action: str, to_state=None, from_state=None,
               target_component=None, change_item_id: Optional[str] = None) -> ChangeArtifact:
    """Dispatch to the provider adapter. Unsupported provider -> manual_review (never raises)."""
    fn = _ADAPTERS.get(provider)
    if fn is None:
        art = _manual(provider, action, target_component, f"No synthesis adapter for provider '{provider}'.")
    else:
        art = fn(action, to_state, from_state, target_component)
    art.change_item_id = change_item_id
    return art
