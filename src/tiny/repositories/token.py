import hashlib
import logging
from datetime import timedelta

from fastapi import Depends

from tiny.core.config import config
from tiny.core.dependencies import get_redis

logger = logging.getLogger(__name__)


class TokenRepository:
    REFRESH_TOKEN_REDIS_KEY_PREFIX = f"{config.redis.cache_prefix}:refresh-token"

    def __init__(self, redis) -> None:
        self.redis = redis

    async def save_refresh_token(
        self, token: str, user_id: int, expires_delta: timedelta
    ):
        # ✅ SHA256 хеш токена = безопасный ключ 64 символа
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        key = f"{self.REFRESH_TOKEN_REDIS_KEY_PREFIX}:{user_id}:{token_hash}"

        await self.redis.setex(key, int(expires_delta.total_seconds()), "1")

    async def verify_refresh_token(self, token: str, user_id: int) -> bool:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        key = f"{self.REFRESH_TOKEN_REDIS_KEY_PREFIX}:{user_id}:{token_hash}"
        return await self.redis.exists(key) > 0

    async def delete_refresh_token(self, token: str, user_id: int) -> None:
        """Удаляет refresh токен (для logout/ротации)"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        key = f"{self.REFRESH_TOKEN_REDIS_KEY_PREFIX}:{user_id}:{token_hash}"
        deleted = await self.redis.delete(key)
        logger.debug(
            "Refresh token deleted",
            extra={"deleted_count": deleted, "user_id": user_id},
        )

    async def delete_all_user_tokens(self, user_id: int) -> int:
        """Удаляет ВСЕ refresh токены пользователя (logout everywhere)"""
        keys_pattern = f"{self.REFRESH_TOKEN_REDIS_KEY_PREFIX}:{user_id}:*"
        keys = await self.redis.keys(keys_pattern)
        if keys:
            deleted = await self.redis.delete(*keys)
            logger.info(
                "All refresh tokens deleted for user",
                extra={"user_id": user_id, "count": deleted},
            )
            return deleted
        return 0


def get_token_repository(redis=Depends(get_redis)) -> TokenRepository:
    return TokenRepository(redis)
