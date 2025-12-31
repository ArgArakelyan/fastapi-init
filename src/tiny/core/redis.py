import logging
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend


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
        Инициализация соединения с Redis и FastAPI-кэша
        """
        try:
            self.redis_client = redis.Redis(
                host=self.host, port=self.port, db=self.db, decode_responses=False
            )
            await self.redis_client.ping()
            FastAPICache.init(RedisBackend(self.redis_client), prefix=self.cache_prefix)
            logger.info("Redis connection established successfully")
        except RedisError:
            logger.error("Failed to connect Redis", exc_info=True)
            raise

    async def disconnect(self):
        """
        Корректное завершение соединения с Redis
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


# глобальный экземпляр
redis_manager = RedisManager(
    host=config.redis.hostname,
    port=config.redis.port,
    db=config.redis.db,
    cache_prefix=config.redis.cache_prefix,
)
