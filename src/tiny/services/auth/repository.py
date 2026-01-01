import logging

from fastapi import Depends
from sqlalchemy import delete, exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tiny.core.config import config
from tiny.core.dependencies import get_redis, get_session
from tiny.services.auth.models import User, UserCache
from tiny.utils.cache import deserialize, serialize

logger = logging.getLogger(__name__)


class UserRepository:
    """User repositry"""

    CACHE_TTL = 300  # 5 minutes
    CACHE_PREFIX = f"{config.redis.cache_prefix}:user"

    def __init__(self, session: AsyncSession, redis) -> None:
        self.session = session
        self.redis = redis

    def _cache_key_exists(self, user_id: int) -> str:
        return f"{self.CACHE_PREFIX}:exists:{user_id}"

    async def create(self, email, password):
        try:
            logger.debug("Creating user", extra={"user": {"email": email}})
            user = User(email=email, password=password)

            self.session.add(user)
            await self.session.commit()
            return user
        except IntegrityError as e:
            await self.session.rollback()
            logger.error(
                "Error creating user",
                extra={"user": {"email": email}},
                exc_info=e,
            )
            raise

    async def get_by_email(self, email: str) -> User | None:
        result = await self.session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_exists_by_id(self, user_id: int) -> int | None:
        cache_key = self._cache_key_exists(user_id)

        cached = await self.redis.get(cache_key)
        if (exists_cached := deserialize(cached)) is not None:
            logger.debug(f"User existence cache hit: {user_id} -> {exists_cached}")
            return user_id if exists_cached else None

        user_exists = await self.session.scalar(
            select(exists().where(User.id == user_id))
        )

        await self.redis.setex(cache_key, self.CACHE_TTL, serialize(user_exists))
        logger.debug(
            f"User existence cache miss and stored: {user_id} -> {user_exists}"
        )

        return user_id if user_exists else None

    async def get_by_id(self, user_id: int):
        user = await self.session.execute(select(User).where(User.id == user_id))
        return user.scalar_one_or_none()

    async def delete_by_id(self, user_id: int) -> bool:
        try:
            await self.session.execute(delete(User).where(User.id == user_id))
            await self.session.commit()
            await self.redis.delete(self._cache_key_exists(user_id))
            logger.info("User deleted successfully", extra={"user": {"id": user_id}})
            return True
        except IntegrityError as e:
            logger.error(
                "Failed to delete user", extra={"user": {"id": user_id}}, exc_info=e
            )
            return False


def get_user_repository(
    session: AsyncSession = Depends(get_session), redis=Depends(get_redis)
) -> UserRepository:
    return UserRepository(session, redis)
