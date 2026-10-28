"""add audit_events (append-only security audit log, A5 enterprise table-stakes)

Revision ID: a7b3e9c2f4d1
Revises: f3a9c1d7e2b5
Create Date: 2026-09-21

Append-only who/what/when log for every authenticated mutating request (see
app/audit_log.py). Distinct from the spine `events` table (domain history). Guarded with
an existence check so a dev SQLite that already grew the table via ``create_all`` is left
alone, while a fresh database (or Postgres) gets the table created.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a7b3e9c2f4d1"
down_revision: Union[str, None] = "f3a9c1d7e2b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(table)


def upgrade() -> None:
    if _has_table("audit_events"):
        return
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("actor_type", sa.String(), nullable=False, server_default="user"),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("method", sa.String(), nullable=True),
        sa.Column("path", sa.String(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("target", sa.String(), nullable=True),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organisations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_org_id", "audit_events", ["org_id"])
    op.create_index("ix_audit_events_actor", "audit_events", ["actor"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_at", "audit_events", ["at"])
    op.create_index("ix_audit_events_org_at", "audit_events", ["org_id", "at"])


def downgrade() -> None:
    if not _has_table("audit_events"):
        return
    op.drop_index("ix_audit_events_org_at", table_name="audit_events")
    op.drop_index("ix_audit_events_at", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_actor", table_name="audit_events")
    op.drop_index("ix_audit_events_org_id", table_name="audit_events")
    op.drop_table("audit_events")
