import logging

from fastapi import Depends
from sqlalchemy import delete, exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tiny.core.dependencies import get_session, get_redis
from tiny.services.auth.models import User
import json

logger = logging.getLogger(__name__)


class UserRepository:
    def __init__(self, session: AsyncSession, redis) -> None:
        self.session = session
        self.redis = redis
        self.cache_prefix = "user"
        self.cache_ttl = 300

    async def create(self, email, password):
        try:
            logger.debug("Creating user", extra={"user": {"email": email}})
            user = User(email=email, password=password)

            self.session.add(user)
            await self.session.commit()
            return user
        except IntegrityError as e:
            logger.error(
                "Error creating user",
                extra={"user": {"email": email}},
                exc_info=e,
            )
            raise

    async def get_by_email(self, email: str) -> User:
        user = await self.session.execute(select(User).where(User.email == email))
        return user.scalar_one_or_none()

    async def get_exists_by_id(self, user_id: int) -> int | None:
        cache_key = f"{self.cache_prefix}:exists:{user_id}"

        cached = await self.redis.get(cache_key)

        if cached is not None:
            exists_in_cache = json.loads(cached)
            logger.debug("User existence from cache", extra={"user_id": user_id})
            return user_id if exists_in_cache else None

        user_exists = await self.session.scalar(
            select(exists().where(User.id == user_id))
        )

        cache_value = json.dumps(bool(user_exists))
        await self.redis.setex(cache_key, self.cache_ttl, cache_value)

        logger.debug("User existence CACHE MISS + stored", extra={"user_id": user_id, "exists": user_exists})

        return user_id if user_exists else None

    async def get_by_id(self, user_id: int):
        user = await self.session.execute(select(User).where(User.id == user_id))
        return user.scalar_one_or_none()

    async def delete_by_id(self, user_id: int) -> bool:
        try:
            await self.session.execute(delete(User).where(User.id == user_id))
            await self.session.commit()
            cache_key = f"{self.cache_prefix}:exists:{user_id}"
            await self.redis.delete(cache_key)
            return True
        except IntegrityError as e:
            logger.error(
                "Failed to delete user", extra={"user": {"id": user_id}}, exc_info=e
            )
            return False


def get_user_repository(session: AsyncSession = Depends(get_session), redis = Depends(get_redis)) -> UserRepository:
    return UserRepository(session, redis)
