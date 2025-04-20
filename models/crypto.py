from pydantic import BaseModel

class CryptoRequest(BaseModel):
    text: str
    key: str = None