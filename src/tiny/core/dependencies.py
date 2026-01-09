from typing import AsyncGenerator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from faststream.rabbit import RabbitBroker
from redis import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from tiny.core.config import config
from tiny.core.database import db
from tiny.core.redis import redis_manager

security = HTTPBearer(auto_error=True)


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


async def get_broker(request: Request) -> RabbitBroker:
    """Получаем уже подключенный брокер из app.state"""
    if not hasattr(request.app.state, "broker"):
        raise HTTPException(503, "RabbitMQ broker unavailable")
    return request.app.state.broker


def verify_bearer_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    if (
        creds.scheme.lower() != "bearer"
        or creds.credentials != config.auth.bearer_token.get_secret_value()
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
