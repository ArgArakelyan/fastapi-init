import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from jose import jwt
from pydantic import BaseModel

from tiny.core.config import config
from tiny.models.auth import AuthRegister
from tiny.models.user import User
from tiny.repositories.user import UserRepository, get_user_repository

logger = logging.getLogger(__name__)


class TokenData(BaseModel):
    user_id: int


class TokenService:
    """Сервис создания и валидации токенов авторизации"""

    def __init__(self):
        self.jwt_secret = config.auth.jwt_secret.get_secret_value()
        self.jwt_encode_algorithm = config.auth.jwt_encode_algorithm

    def create_access_token(self, user_id: int) -> str:
        expires = datetime.now(timezone.utc) + timedelta(
            minutes=config.auth.access_token_expire_minutes
        )

        payload = {"type": "access", "sub": str(user_id), "exp": expires}
        logger.debug("Access token created", extra={"user_id": user_id})
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_encode_algorithm)

    def decode_token(self, token: str) -> TokenData:
        try:
            payload = jwt.decode(
                token, self.jwt_secret, algorithms=[self.jwt_encode_algorithm]
            )

            if payload.get("type") != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                )

            return TokenData(user_id=int(payload["sub"]))
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.JWTError as e:
            logger.warning(
                "JWT Error on decode", extra={"access_token": token, "error": str(e)}
            )
            raise HTTPException(status_code=401, detail="Invalid token")


def get_token_service() -> TokenService:
    return TokenService()


class AuthService:
    """Сервис авторизации"""

    def __init__(self, repo: UserRepository, token_service: TokenService):
        self.user_repo = repo
        self.token_service = token_service

    @staticmethod
    def verify_password(hashed_password: str, password: str) -> bool:
        """
        Проверяет пароль против хеша.
        """
        if not password or not hashed_password:
            return False

        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
        except (ValueError, TypeError):
            # Некорректный формат хеша
            logger.warning("Invalid password hash")
            return False

    async def register(self, user_in: AuthRegister):
        """New user registration"""
        exists = await self.user_repo.get_by_email(user_in.email)

        if exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="User already exists"
            )

        hashed_password = bcrypt.hashpw(
            user_in.password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        user = await self.user_repo.create(
            email=user_in.email, password=hashed_password
        )

        logger.info("User registered", extra={"user_id": user.id})
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

        access_token = self.token_service.create_access_token(user.id)
        logger.debug("User logged in", extra={"user_id": user.id})

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user.id,
            "email": user.email,
        }


def get_auth_service(
        repo: UserRepository = Depends(get_user_repository),
        token_service: TokenService = Depends(get_token_service),
) -> AuthService:
    return AuthService(repo, token_service)


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
        auth_service: AuthService = Depends(get_auth_service),
) -> int | None:
    token = request.cookies.get("access_token")
    if not token:
        return None

    try:
        token_data = auth_service.token_service.decode_token(token)
    except HTTPException:
        return None

    return token_data.user_id


CurrentUser = Annotated[User, Depends(get_current_user)]
