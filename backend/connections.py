# app/schemas/connections.py
from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional
from enum import Enum

class PingType(str, Enum):
    details = "details"
    uptodate = "uptodate"
    reshare_request = "reshare_request"

class PingRequest(BaseModel):
    ping_type: PingType

class ConnectionRequestCreate(BaseModel):
    target_user_id: UUID
    requested_pool_id: str
    ciphertext: str # base64
    encrypted_pool_key: Optional[str] = None # base64

class ConnectionRequestResponse(BaseModel):
    request_id: UUID
    from_user_id: UUID
    to_user_id: UUID
    requested_pool_id: str
    ciphertext: str # base64
    encrypted_pool_key: Optional[str] = None # base64
    status: str
    created_at: datetime
    responded_at: Optional[datetime] = None

    # Public profile fields of the user who sent the request
    from_user_public_display_name: Optional[str] = None
    from_user_public_headline: Optional[str] = None
    from_user_public_evertouch_id: Optional[str] = None

    class Config:
        from_attributes = True

class ConnectionRequestAccept(BaseModel):
    selected_pool_id: str
    ciphertext: Optional[str] = None # initial encrypted payload B->A
    encrypted_pool_key: Optional[str] = None # base64

class ConnectionResponse(BaseModel):
    connection_id: UUID
    owner_user_id: UUID
    target_user_id: UUID
    pool_id: str
    created_at: datetime
    updated_at: datetime

    # Public profile fields of the target user
    target_user_public_display_name: Optional[str] = None
    target_user_public_headline: Optional[str] = None
    target_user_public_evertouch_id: Optional[str] = None
    target_user_public_key: Optional[str] = None

    class Config:
        from_attributes = True

class ConnectionUpdate(BaseModel):
    pool_id: str
    ciphertext: str # new encrypted payload for this pool
    encrypted_pool_key: Optional[str] = None # base64

class SharedPayloadCreate(BaseModel):
    target_user_id: UUID
    ciphertext: str # base64
    encrypted_pool_key: Optional[str] = None # base64

class SharedPayloadResponse(BaseModel):
    payload_id: UUID
    from_user_id: UUID
    to_user_id: UUID
    ciphertext: str # base64
    encrypted_pool_key: Optional[str] = None # base64
    updated_at: datetime

    # Public profile fields of the sender (to support feeds)
    from_user_public_display_name: Optional[str] = None
    from_user_public_headline: Optional[str] = None

    class Config:
        from_attributes = True
