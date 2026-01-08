import logging
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from jose import jwt
from pydantic import BaseModel

from tiny.core.config import config

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