import logging
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from jose import jwt

from tiny.core.config import config
from tiny.models.token import TokenData
from tiny.repositories.token import TokenRepository, get_token_repository

logger = logging.getLogger(__name__)


class TokenService:
    """Сервис создания и валидации токенов авторизации"""

    def __init__(self, token_repo: TokenRepository = None) -> None:
        self.jwt_secret = config.auth.jwt_secret.get_secret_value()
        self.jwt_encode_algorithm = config.auth.jwt_encode_algorithm
        self.token_repo = token_repo

    async def create_tokens_pair(self, user_id: int) -> dict[str, str]:
        """Создает пару токенов и сохраняет refresh в Redis"""
        access_token = self.create_access_token(user_id)
        refresh_token = self.create_refresh_token(user_id)

        expires_delta = timedelta(days=config.auth.refresh_token_expire_days)
        await self.token_repo.save_refresh_token(refresh_token, user_id, expires_delta)

        return {"access_token": access_token, "refresh_token": refresh_token}

    async def refresh_access_token(self, refresh_token: str) -> dict[str, str]:
        """Обновляет access токен, ротирует refresh"""
        token_data = self.decode_token(refresh_token)
        if token_data.token_type != "refresh":
            raise HTTPException(401, "Invalid refresh token")

        if not await self.token_repo.verify_refresh_token(
            refresh_token, token_data.user_id
        ):
            raise HTTPException(401, "Refresh token not found or expired")

        await self.token_repo.delete_refresh_token(refresh_token, token_data.user_id)

        new_tokens = await self.create_tokens_pair(token_data.user_id)
        return new_tokens

    def create_access_token(self, user_id: int) -> str:
        expires = datetime.now(timezone.utc) + timedelta(
            minutes=config.auth.access_token_expire_minutes
        )

        payload = {"type": "access", "sub": str(user_id), "exp": expires}
        logger.debug("Access token created", extra={"user_id": user_id})
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_encode_algorithm)

    def create_refresh_token(self, user_id: int) -> str:
        expires = datetime.now(timezone.utc) + timedelta(
            days=config.auth.refresh_token_expire_days
        )

        payload = {"type": "refresh", "sub": str(user_id), "exp": expires}
        logger.debug("Refresh token created", extra={"user_id": user_id})
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_encode_algorithm)

    def create_password_reset_token(self, email: str) -> str:
        expires = datetime.now(timezone.utc) + timedelta(minutes=5)

        payload = {"type": "password_reset", "sub": str(email), "exp": expires}
        logger.debug("Password reset token created", extra={"email": email})
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_encode_algorithm)

    def decode_token(self, token: str) -> TokenData:
        try:
            payload = jwt.decode(
                token, self.jwt_secret, algorithms=[self.jwt_encode_algorithm]
            )

            token_type = payload.get("type")

            if token_type not in ["access", "refresh"]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                )

            return TokenData(user_id=int(payload["sub"]), token_type=token_type)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.JWTError as e:
            logger.warning(
                "JWT Error on decode", extra={"access_token": token, "error": str(e)}
            )
            raise HTTPException(status_code=401, detail="Invalid token")


def get_token_service(
    token_repo: TokenRepository = Depends(get_token_repository),
) -> TokenService:
    return TokenService(token_repo)
