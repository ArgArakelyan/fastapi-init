from datetime import datetime
from typing import Optional

import bcrypt
from jose import jwt
from pydantic import BaseModel, field_validator
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from tiny.core.config import config
from tiny.core.database import Base


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, index=True)
    password: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.now
    )

    def verify_password(self, password: str) -> bool:
        if not password or not self.password:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), self.password.encode("utf-8"))

    @property
    def token(self):
        data = {
            "user_id": self.id,
            "email": self.email,
        }
        return jwt.encode(
            data, config.auth.jwt_secret.get_secret_value(), algorithm="HS256"
        )


class UserCache(BaseModel):
    id: int
    is_active: bool
    email: str
    created_at: Optional[str] = None


class AuthBase(BaseModel):
    email: str
    password: str


class AuthLogin(AuthBase):
    @field_validator("password")  # noqa
    @classmethod
    def password_required(cls, v):
        if not v:
            raise ValueError("Must not be empty string")
        return v


class AuthRegister(AuthBase):
    @field_validator("password", mode="before")
    @classmethod
    def hash(cls, v):
        if not v:
            return None
        return hash_password(str(v))
