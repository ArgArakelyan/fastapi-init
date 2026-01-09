import logging
from typing import Optional

from fastapi import Depends
from sqlalchemy import delete, exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tiny.core.config import config
from tiny.core.dependencies import get_redis, get_session
from tiny.models.user import User, UserAuth, UserRead
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

    def _cache_key_user(self, user_id: int) -> str:
        return f"{self.CACHE_PREFIX}:by_id:{user_id}"

    async def _get_user_cache(self, user_id: int) -> Optional[UserRead]:
        cache_key = self._cache_key_user(user_id)
        cached = await self.redis.get(cache_key)
        if not cached:
            return None

        data = deserialize(cached)
        if data is None:
            return None

        try:
            return UserRead.model_validate(data)
        except Exception:  # noqa
            # если схема изменилась/битые данные – просто считаем кэш протухшим
            return None

    async def _set_user_cache(self, user: UserRead) -> None:
        cache_key = self._cache_key_user(user.id)
        await self.redis.setex(cache_key, self.CACHE_TTL, serialize(user.model_dump()))

    async def _invalidate_user_cache(self, user_id: int) -> None:
        await self.redis.delete(self._cache_key_user(user_id))

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

    async def get_all(self, limit, offset):
        query = select(User).order_by(User.created_at)

        if limit > 0:
            query = query.offset(offset).limit(limit)

        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_by_email(self, email: str) -> UserAuth | None:
        result = await self.session.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user:
            return None

        return UserAuth(id=user.id, password=user.password, email=user.email)

    async def get_exists_by_id(self, user_id: int) -> int | None:
        cache_key = self._cache_key_exists(user_id)

        cached = await self.redis.get(cache_key)
        if (exists_cached := deserialize(cached)) is not None:
            logger.debug("User existence cache hit")
            return user_id if exists_cached else None

        user_exists = await self.session.scalar(
            select(exists().where(User.id == user_id))
        )

        await self.redis.setex(cache_key, self.CACHE_TTL, serialize(user_exists))
        logger.debug("User existence cache miss and stored")

        return user_id if user_exists else None

    async def get_by_id(self, user_id: int):
        cached_user = await self._get_user_cache(user_id)
        if cached_user:
            logger.debug("User cache hit", extra={"user": {"id": user_id}})
            return cached_user

        logger.debug("User cache miss", extra={"user": {"id": user_id}})

        result = await self.session.execute(select(User).where(User.id == user_id))
        user: User | None = result.scalar_one_or_none()
        if not user:
            return None

        user_read = UserRead(id=user.id, email=user.email, created_at=user.created_at)

        await self._set_user_cache(user_read)

        return user_read

    async def delete_by_id(self, user_id: int) -> bool:
        try:
            await self.session.execute(delete(User).where(User.id == user_id))
            await self.session.commit()
            await self.redis.delete(self._cache_key_exists(user_id))
            await self._invalidate_user_cache(user_id)
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
