# app/schemas/directory.py
from pydantic import BaseModel
from uuid import UUID
from typing import List, Optional

from enum import Enum

class ConnectionStatus(str, Enum):
    connected = "connected"
    pending = "pending"
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
    user_id: UUID
    email: str
    public_display_name: Optional[str] = None
    public_headline: Optional[str] = None
    public_evertouch_id: Optional[str] = None
    connection_status: ConnectionStatus = ConnectionStatus.not_connected

    class Config:
        from_attributes = True

class UserSearchResponse(BaseModel):
    results: List[UserSearchResult]
