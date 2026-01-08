# app/schemas/crypto.py
from pydantic import BaseModel
from uuid import UUID

class PublicKeyUpdate(BaseModel):
    public_key: str # base64
    encrypted_private_key_bundle: str # base64
    recovery_salt: str # base64

class PublicKeyResponse(BaseModel):
    user_id: UUID
    public_key: str # base64

    class Config:
        from_attributes = True
