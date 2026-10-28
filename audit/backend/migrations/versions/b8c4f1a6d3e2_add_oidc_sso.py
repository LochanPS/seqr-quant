"""add oidc_providers + users.oidc_subject (enterprise SSO, A5)

Revision ID: b8c4f1a6d3e2
Revises: a7b3e9c2f4d1
Create Date: 2026-09-21

Per-org OIDC SSO. `oidc_providers` holds each org's IdP config (client secret encrypted at
rest — see app/sso/crypto.py); `users.oidc_subject` binds a SeQr account to its IdP identity.
Guarded with existence checks so a dev SQLite that already grew these via ``create_all`` is
left alone, while a fresh database (or Postgres) gets them created.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b8c4f1a6d3e2"
down_revision: Union[str, None] = "a7b3e9c2f4d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table)


def _has_column(table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade() -> None:
    if not _has_column("users", "oidc_subject"):
        op.add_column("users", sa.Column("oidc_subject", sa.String(), nullable=True))
        op.create_index("ix_users_oidc_subject", "users", ["oidc_subject"])

    if not _has_table("oidc_providers"):
        op.create_table(
            "oidc_providers",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("org_id", sa.Uuid(), nullable=False),
            sa.Column("display_name", sa.String(), nullable=False, server_default="SSO"),
            sa.Column("issuer", sa.String(), nullable=False),
            sa.Column("client_id", sa.String(), nullable=False),
            sa.Column("client_secret_encrypted", sa.String(), nullable=False),
            sa.Column("discovery_url", sa.String(), nullable=True),
            sa.Column("scopes", sa.String(), nullable=False, server_default="openid email profile groups"),
            sa.Column("groups_claim", sa.String(), nullable=False, server_default="groups"),
            sa.Column("group_role_map", sa.JSON(), nullable=False),
            sa.Column("default_role", sa.String(), nullable=False, server_default="member"),
            sa.Column("email_domain", sa.String(), nullable=True),
            sa.Column("auto_provision", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["org_id"], ["organisations.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("org_id", name="uq_oidc_providers_org_id"),
        )
        op.create_index("ix_oidc_providers_org_id", "oidc_providers", ["org_id"])
        op.create_index("ix_oidc_providers_email_domain", "oidc_providers", ["email_domain"])


def downgrade() -> None:
    if _has_table("oidc_providers"):
        op.drop_index("ix_oidc_providers_email_domain", table_name="oidc_providers")
        op.drop_index("ix_oidc_providers_org_id", table_name="oidc_providers")
        op.drop_table("oidc_providers")
    if _has_column("users", "oidc_subject"):
        op.drop_index("ix_users_oidc_subject", table_name="users")
        op.drop_column("users", "oidc_subject")
