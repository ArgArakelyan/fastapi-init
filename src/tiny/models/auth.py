import bcrypt
from pydantic import BaseModel, field_validator


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


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
