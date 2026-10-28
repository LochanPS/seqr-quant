from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import settings

engine = create_async_engine(settings.async_database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# Synchronous engine for Celery tasks (strips async driver prefix)
_sync_engine = create_engine(settings.sync_database_url, echo=False)
SyncSessionLocal = sessionmaker(bind=_sync_engine, class_=Session, expire_on_commit=False)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
