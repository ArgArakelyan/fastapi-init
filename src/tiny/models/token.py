from pydantic import BaseModel


class TokenData(BaseModel):
    user_id: int
    token_type: str
