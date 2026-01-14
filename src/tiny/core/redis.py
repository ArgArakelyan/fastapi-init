"""
Настройка подключения к Redis
"""

import asyncio
import logging
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from tiny.core.config import config

logger = logging.getLogger(__name__)


class RedisManager:
    def __init__(self, host, port, db, cache_prefix):
        self.host = host
        self.port = port
        self.db = db
        self.cache_prefix = cache_prefix
        self.redis_client: Optional[redis.Redis] = None

    async def connect(self):
        """
        Инициализация соединения с Redis
        """
        try:
            self.redis_client = redis.Redis(
                host=self.host, port=self.port, db=self.db, decode_responses=False
            )
            await self.redis_client.ping()
            logger.info("Redis connection established successfully")
        except RedisError:
            logger.error("Failed to connect Redis", exc_info=True)
            raise

    async def disconnect(self):
        """
        Завершение соединения с Redis (кладется в lifespan для корректного завершения App)
        """
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis connection closed")

    async def get_client(self):
        """
        Получение текущего redis клиента
        """
        if self.redis_client is None:
            await self.connect()
        return self.redis_client

    # базовые команды redis

    async def get(self, key: str):
        client = await self.get_client()
        try:
            return await client.get(key)
        except RedisError:
            logger.error("Failed to get {} from Redis", key)
            return None

    async def set(self, key: str, value: Any, expire: Optional[int] = None):
        client = await self.get_client()
        try:
            result = await client.set(key, value, ex=expire)
            return result is True
        except RedisError:
            logger.error("Failed to set {} from Redis", key)
            return False

    async def delete(self, key: str):
        client = await self.get_client()
        try:
            result = await client.delete(key)
            return result > 0
        except RedisError:
            logger.error("Failed to delete {} from Redis", key)
            return False

    async def exists(self, key: str):
        client = await self.get_client()
        try:
            result = await client.exists(key)
            return result > 0
        except RedisError:
            logger.error("Failed to to check existence of key {} from Redis", key)
            return False

    async def check_alive(self, timeout: float = 0.5) -> bool:
        client = await self.get_client()
        try:
            await asyncio.wait_for(client.ping(), timeout=timeout)
            return True
        except (RedisError, asyncio.TimeoutError):
            logger.error("Redis health check failed", exc_info=True)
            return False


# глобальный экземпляр
redis_manager = RedisManager(
    host=config.redis.hostname,
    port=config.redis.port,
    db=config.redis.db,
    cache_prefix=config.redis.cache_prefix,
)
