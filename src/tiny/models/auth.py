import bcrypt
from pydantic import BaseModel


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


class AuthBase(BaseModel):
    email: str
    password: str
