import logging
import random
from typing import Annotated

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from faststream.rabbit import RabbitBroker

from tiny.core.config import config
from tiny.core.dependencies import get_broker, get_redis
from tiny.models.auth import AuthBase
from tiny.models.user import User
from tiny.repositories.user import UserRepository, get_user_repository
from tiny.services.token import TokenService, get_token_service

logger = logging.getLogger(__name__)


class AuthService:
    """Сервис авторизации"""

    def __init__(
        self,
        repo: UserRepository,
        token_service: TokenService,
        redis,
        broker: RabbitBroker,
    ):
        self.user_repo = repo
        self.token_service = token_service
        self.redis = redis
        self.broker = broker

    @staticmethod
    def verify_password(hashed_password: str, password: str) -> bool:
        """Простейший рабочий вариант"""
        if not password or not hashed_password:
            return False

        try:
            return bcrypt.checkpw(password.encode(), hashed_password.encode())
        except (ValueError, TypeError):
            # Некорректный формат хеша
            logger.warning("Invalid password hash")
            return False

    async def register(self, user_in: AuthBase):
        """New user registration"""
        exists = await self.user_repo.get_by_email(user_in.email)

        if exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="User already exists"
            )

        hashed_password = bcrypt.hashpw(
            user_in.password.encode(), bcrypt.gensalt()
        ).decode()

        user = await self.user_repo.create(
            email=user_in.email, password=hashed_password
        )
        return user

    async def login(self, email, password, client_ip, user_agent):
        logger.debug(
            "Login attempt",
            extra={
                "user": {
                    "email": email,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                }
            },
        )

        user = await self.user_repo.get_by_email(email)

        # Проверяем пароль через сервис для защиты от timing attack
        if not user or not self.verify_password(user.password, password):
            logger.warning("Failed login", extra={"email": email})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )

        tokens = await self.token_service.create_tokens_pair(user.id)
        logger.info("User logged in", extra={"user_id": user.id})

        return {
            **tokens,
            "token_type": "bearer",
            "user_id": user.id,
            "email": user.email,
        }

    async def refresh_token(self, refresh_token: str):
        """Эндпоинт для обновления токенов"""
        return await self.token_service.refresh_access_token(refresh_token)

    async def reset_password(self, email: str):
        user = await self.user_repo.get_by_email(email)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        logger.info("User requested password reset", extra={"email": email})

        reset_code = "".join([str(random.randint(0, 9)) for _ in range(6)])

        redis_key = f"{config.redis.cache_prefix}:reset-password:{email}"
        await self.redis.setex(redis_key, 600, reset_code)
        await self.broker.publish(
            message={"user_id": user.id, "email": email, "reset_code": reset_code},
            queue="email.reset_password",
            expiration=600,
            correlation_id=str(user.id),
        )
        logger.info(
            "Password reset code sent to broker",
            extra={"email": email},
        )

        return {
            "result": "success",
            "msg": f"Password reset sent to your email: {email}",
        }

    async def verify_reset_code(self, email: str, reset_code: str):
        redis_key = f"{config.redis.cache_prefix}:reset-password:{email}"
        stored_code = await self.redis.get(redis_key)

        if not stored_code or stored_code.decode() != reset_code:
            raise HTTPException(400, "Invalid or expired code")

        await self.redis.delete(redis_key)

        reset_token = self.token_service.create_password_reset_token(email)

        return {"reset_token": reset_token, "message": "Code verified"}


def get_auth_service(
    repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
    redis=Depends(get_redis),
    broker=Depends(get_broker),
) -> AuthService:
    return AuthService(repo, token_service, redis, broker)


async def get_current_user(
    request: Request,
    repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
):
    token = request.cookies.get("access_token")
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing in cookies",
        )

    token_data = token_service.decode_token(token)
    user_id_exists = await repo.get_exists_by_id(token_data.user_id)
    if user_id_exists is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return CurrentUser(id=user_id_exists)


async def get_optional_current_user(
    request: Request,
    token_service: TokenService = Depends(get_token_service),
) -> int | None:
    token = request.cookies.get("access_token")
    if not token:
        return None

    try:
        token_data = token_service.decode_token(token)
    except HTTPException:
        return None

    return token_data.user_id


CurrentUser = Annotated[User, Depends(get_current_user)]
