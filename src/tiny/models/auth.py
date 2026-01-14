from pydantic import BaseModel


class AuthBase(BaseModel):
    email: str
    password: str
