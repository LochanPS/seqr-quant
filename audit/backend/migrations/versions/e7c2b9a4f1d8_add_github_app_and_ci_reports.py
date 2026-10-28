"""add github_installations + ci_reports (CI-4 hosted GitHub App)

Revision ID: e7c2b9a4f1d8
Revises: d5e8f1a2c3b4
Create Date: 2026-09-08

Two tables for the CI/dashboard sync:

* ``ci_reports`` — introduced with CI-2 (PR findings → dashboard) but never given an
  Alembic revision; it only existed via the dev SQLite ``create_all``. Added here so a
  Postgres deployment actually has the table. Guarded with ``checkfirst`` semantics via an
  existence check so a database that already has it (dev) is not disturbed.
* ``github_installations`` — maps a GitHub App installation to a SeQr org so a webhook PR
  scan (CI-4) can be synced into the right customer's CBOM.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e7c2b9a4f1d8"
down_revision: Union[str, None] = "d5e8f1a2c3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def upgrade() -> None:
    if not _has_table("ci_reports"):
        op.create_table(
            "ci_reports",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column(
                "org_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False,
            ),
            sa.Column("actor", sa.String(), nullable=True),
            sa.Column("repo", sa.String(), nullable=False),
            sa.Column("pr_number", sa.Integer(), nullable=True),
            sa.Column("commit_sha", sa.String(), nullable=True),
            sa.Column("branch", sa.String(), nullable=True),
            sa.Column("source", sa.String(), nullable=False, server_default="github"),
            sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("summary", sa.JSON(), nullable=True),
            sa.Column("findings", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
        )
        op.create_index("ix_ci_reports_org_id", "ci_reports", ["org_id"])

    if not _has_table("github_installations"):
        op.create_table(
            "github_installations",
            sa.Column("installation_id", sa.BigInteger(), primary_key=True, autoincrement=False),
            sa.Column(
                "org_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False,
            ),
            sa.Column("account_login", sa.String(), nullable=True),
            sa.Column("account_type", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
        )
        op.create_index(
            "ix_github_installations_org_id", "github_installations", ["org_id"]
        )


def downgrade() -> None:
    if _has_table("github_installations"):
        op.drop_index("ix_github_installations_org_id", table_name="github_installations")
        op.drop_table("github_installations")
    # ci_reports predates this revision conceptually (CI-2); leave it in place on downgrade
    # so we don't drop a table other revisions/None-Alembic dev setups assume exists.
