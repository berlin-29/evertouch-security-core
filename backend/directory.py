# app/schemas/directory.py
from pydantic import BaseModel
from uuid import UUID
from typing import List, Optional

from enum import Enum

class ConnectionStatus(str, Enum):
    connected = "connected"
    pending = "pending"
    pending_incoming = "pending_incoming"
    pending_outgoing = "pending_outgoing"
    not_connected = "not_connected"

class UserLookupRequest(BaseModel):
    query: str

class EmailListRequest(BaseModel):
    emails: List[str]

    class Config:
        json_schema_extra = {
            "example": {
                "emails": ["user1@example.com", "user2@example.com"]
            }
        }

class UserSearchResult(BaseModel):
    id: UUID
    user_id: UUID
    email: str
    public_display_name: str = ""
    public_headline: str = ""
    public_evertouch_id: str = ""
    connection_status: ConnectionStatus = ConnectionStatus.not_connected

    class Config:
        from_attributes = True

class UserSearchResponse(BaseModel):
    results: List[UserSearchResult]
