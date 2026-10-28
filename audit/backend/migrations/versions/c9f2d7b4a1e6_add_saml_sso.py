"""add saml_providers + saml_replay_ids + users.saml_subject (enterprise SSO, A5)

Revision ID: c9f2d7b4a1e6
Revises: b8c4f1a6d3e2
Create Date: 2026-09-29

Per-org SAML 2.0 SSO, mirroring the OIDC rev (b8c4f1a6d3e2). `saml_providers` holds each org's
IdP config (the signing cert is public — no encryption, unlike the OIDC client secret);
`saml_replay_ids` is the single-use assertion cache (replay protection); `users.saml_subject`
binds a SeQr account to its SAML NameID. Guarded with existence checks so a dev SQLite that
already grew these via ``create_all`` is left alone, while a fresh database (or Postgres) gets
them created.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c9f2d7b4a1e6"
down_revision: Union[str, None] = "b8c4f1a6d3e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table)


def _has_column(table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade() -> None:
    if not _has_column("users", "saml_subject"):
        op.add_column("users", sa.Column("saml_subject", sa.String(), nullable=True))
        op.create_index("ix_users_saml_subject", "users", ["saml_subject"])

    if not _has_table("saml_providers"):
        op.create_table(
            "saml_providers",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("org_id", sa.Uuid(), nullable=False),
            sa.Column("display_name", sa.String(), nullable=False, server_default="SSO"),
            sa.Column("idp_entity_id", sa.String(), nullable=False),
            sa.Column("idp_sso_url", sa.String(), nullable=False),
            sa.Column("idp_slo_url", sa.String(), nullable=True),
            sa.Column("idp_x509_cert", sa.String(), nullable=False),
            sa.Column("sp_entity_id", sa.String(), nullable=True),
            sa.Column("want_assertions_signed", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("name_id_format", sa.String(), nullable=True),
            sa.Column("email_attribute", sa.String(), nullable=True),
            sa.Column("groups_attribute", sa.String(), nullable=False, server_default="groups"),
            sa.Column("group_role_map", sa.JSON(), nullable=False),
            sa.Column("default_role", sa.String(), nullable=False, server_default="member"),
            sa.Column("email_domain", sa.String(), nullable=True),
            sa.Column("auto_provision", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["org_id"], ["organisations.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("org_id", name="uq_saml_providers_org_id"),
        )
        op.create_index("ix_saml_providers_org_id", "saml_providers", ["org_id"])
        op.create_index("ix_saml_providers_email_domain", "saml_providers", ["email_domain"])

    if not _has_table("saml_replay_ids"):
        op.create_table(
            "saml_replay_ids",
            sa.Column("assertion_id", sa.String(), nullable=False),
            sa.Column("org_id", sa.Uuid(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("assertion_id"),
        )
        op.create_index("ix_saml_replay_ids_org_id", "saml_replay_ids", ["org_id"])
        op.create_index("ix_saml_replay_ids_expires_at", "saml_replay_ids", ["expires_at"])


def downgrade() -> None:
    if _has_table("saml_replay_ids"):
        op.drop_index("ix_saml_replay_ids_expires_at", table_name="saml_replay_ids")
        op.drop_index("ix_saml_replay_ids_org_id", table_name="saml_replay_ids")
        op.drop_table("saml_replay_ids")
    if _has_table("saml_providers"):
        op.drop_index("ix_saml_providers_email_domain", table_name="saml_providers")
        op.drop_index("ix_saml_providers_org_id", table_name="saml_providers")
        op.drop_table("saml_providers")
    if _has_column("users", "saml_subject"):
        op.drop_index("ix_users_saml_subject", table_name="users")
        op.drop_column("users", "saml_subject")
