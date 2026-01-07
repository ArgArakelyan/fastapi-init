from typing import AsyncGenerator

from redis import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from tiny.core.database import db
from tiny.core.redis import redis_manager


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with db.session() as session:
        yield session


async def get_redis() -> AsyncGenerator[Redis, None]:
    """Dependency that provides Redis client with proper lifecycle"""
    client = await redis_manager.get_client()
    if client is None:
        raise RuntimeError("Redis not connected")
    try:
        yield client
    finally:
        pass
