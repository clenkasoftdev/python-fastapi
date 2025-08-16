from pydantic import BaseModel
from typing import Optional


class TokenData(BaseModel):
    sub: str
    username: Optional[str] = None
