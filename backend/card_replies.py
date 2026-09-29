# app/schemas/card_replies.py
import base64
import binascii
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# A reply carries a handful of short contact fields. The caps leave plenty of
# headroom for that and stop the public endpoint from being used as free
# blob storage.
MAX_REPLY_CIPHERTEXT_CHARS = 16 * 1024
MAX_REPLY_ENCRYPTED_KEY_CHARS = 1024


class CardReplyCreate(BaseModel):
    ephemeral_public_key: str = Field(..., max_length=128) # base64 raw X25519
    ciphertext: str = Field(..., min_length=1, max_length=MAX_REPLY_CIPHERTEXT_CHARS) # base64 JSON EncryptedData
    encrypted_key: str = Field(..., min_length=1, max_length=MAX_REPLY_ENCRYPTED_KEY_CHARS) # base64 JSON EncryptedData

    @field_validator("ephemeral_public_key")
    @classmethod
    def validate_ephemeral_public_key(cls, v: str) -> str:
        value = v.strip()
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("ephemeral_public_key must be base64")
        if len(raw) != 32:
            raise ValueError("ephemeral_public_key must be a 32-byte X25519 key")
        return value


class CardReplyCreateResponse(BaseModel):
    reply_id: UUID


class CardReplyResponse(BaseModel):
    reply_id: UUID
    share_id: Optional[UUID] = None
    card_label: Optional[str] = None
    ephemeral_public_key: str
    ciphertext: str
    encrypted_key: str
    created_at: datetime
    read_at: Optional[datetime] = None
    converted_user_id: Optional[UUID] = None
    converted_user_public_display_name: Optional[str] = None
