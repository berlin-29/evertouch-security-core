# app/schemas/link_cards.py
from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional
from app.schemas.auth import UserPublicResponse

class LinkCardCreate(BaseModel):
    pool_id: str
    ciphertext: str # base64 encoded
    encrypted_secret: Optional[str] = None # Secret encrypted with user's profile key
    label: Optional[str] = None
    expires_at: Optional[datetime] = None

class LinkCardUpdate(BaseModel):
    ciphertext: Optional[str] = None # base64 encoded
    encrypted_secret: Optional[str] = None
    label: Optional[str] = None
    expires_at: Optional[datetime] = None

class LinkCardResponse(BaseModel):
    share_id: UUID
    user_id: UUID
    pool_id: str
    ciphertext: str # base64 encoded
    encrypted_secret: Optional[str] = None
    label: Optional[str] = None
    expires_at: Optional[datetime] = None
    revoked: bool
    view_count: int
    # Owner-facing only. Deliberately absent from LinkCardShareResponse below: a
    # viewer must not learn when anyone else opened the card. Clients round it to
    # a day before showing it.
    last_viewed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class LinkCardShareResponse(BaseModel): # For the public GET /link-cards/{share_id} endpoint
    ciphertext: str # base64 encoded
    label: Optional[str] = None
    expires_at: Optional[datetime] = None
    revoked: bool
    owner: UserPublicResponse
    # Lets an anonymous viewer seal a card reply to the owner. A public key;
    # owner.user_id is already public on this endpoint.
    owner_public_key: Optional[str] = None

    class Config:
        from_attributes = True

class LinkCardCreateResponse(BaseModel): # Response for POST /link-cards
    share_id: UUID
