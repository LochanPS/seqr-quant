import uuid
from datetime import datetime

from sqlalchemy import DateTime, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class BlogPost(Base):
    """Marketing blog / announcements — operator-authored, public when published."""
    __tablename__ = "blog_posts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    excerpt: Mapped[str | None] = mapped_column(String, nullable=True)     # SEO meta / listing summary
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")     # markdown
    status: Mapped[str] = mapped_column(String, default="draft", nullable=False)  # draft | published
    author_email: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
