"""Public blog API — published posts only (for the marketing site + SEO)."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.database import get_db
from app.models.blog_post import BlogPost

router = APIRouter()


class BlogListItem(BaseModel):
    slug: str
    title: str
    excerpt: Optional[str]
    tags: list
    published_at: Optional[datetime]


class BlogPostOut(BlogListItem):
    body: str


@router.get("", response_model=list[BlogListItem])
async def list_published(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(BlogPost)
        .where(BlogPost.status == "published")
        .order_by(BlogPost.published_at.desc().nullslast())
    )).scalars().all()
    return [
        BlogListItem(slug=p.slug, title=p.title, excerpt=p.excerpt,
                     tags=p.tags or [], published_at=p.published_at)
        for p in rows
    ]


@router.get("/{slug}", response_model=BlogPostOut)
async def get_published(slug: str, db: AsyncSession = Depends(get_db)):
    post = (await db.execute(
        select(BlogPost).where(BlogPost.slug == slug, BlogPost.status == "published")
    )).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return BlogPostOut(
        slug=post.slug, title=post.title, excerpt=post.excerpt,
        tags=post.tags or [], published_at=post.published_at, body=post.body,
    )
