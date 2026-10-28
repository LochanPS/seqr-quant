"""add user.token_version, organisation.status, blog_posts

Revision ID: b2f7a1c9d8e3
Revises: 1ecef0fb8cb8
Create Date: 2026-06-28

Brings the schema up to date with model changes made after the report migration:
- users.token_version (JWT revocation on logout)
- organisations.status (active | suspended)
- blog_posts table (marketing CMS)

Without this, `alembic upgrade head` on a fresh Postgres builds an old schema and the
app 500s on register/login (missing users.token_version) and on /blog (missing table).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2f7a1c9d8e3"
down_revision: Union[str, None] = "1ecef0fb8cb8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "organisations",
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
    )
    op.create_table(
        "blog_posts",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("excerpt", sa.String(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="draft"),
        sa.Column("author_email", sa.String(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_blog_posts_slug", "blog_posts", ["slug"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_blog_posts_slug", table_name="blog_posts")
    op.drop_table("blog_posts")
    op.drop_column("organisations", "status")
    op.drop_column("users", "token_version")
