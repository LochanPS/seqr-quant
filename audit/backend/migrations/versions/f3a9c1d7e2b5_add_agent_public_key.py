"""add api_keys.agent_public_key (discovery-agent signing key, PRD 15 §5/§6/§8)

Revision ID: f3a9c1d7e2b5
Revises: e7c2b9a4f1d8
Create Date: 2026-09-15

Binds an Ed25519 public key (PEM or base64 raw) to an `agent`-scoped credential. First upload
enrols the key (TOFU); afterwards every observations batch and every air-gap import envelope
must carry a signature the stored key verifies. Nullable so existing credentials are unaffected.

Guarded with an existence check: a dev SQLite that already grew the column via ``create_all`` is
left alone, while a fresh database (or Postgres) gets the column added.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f3a9c1d7e2b5"
down_revision: Union[str, None] = "e7c2b9a4f1d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    if not _has_column("api_keys", "agent_public_key"):
        op.add_column("api_keys", sa.Column("agent_public_key", sa.String(), nullable=True))


def downgrade() -> None:
    if _has_column("api_keys", "agent_public_key"):
        op.drop_column("api_keys", "agent_public_key")
