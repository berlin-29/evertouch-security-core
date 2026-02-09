from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional

class UserNoteBase(BaseModel):
    ciphertext: str

class UserNoteCreate(UserNoteBase):
    pass

class UserNoteUpdate(UserNoteBase):
    pass

class UserNoteResponse(UserNoteBase):
    id: UUID
    owner_user_id: UUID
    target_user_id: UUID
    updated_at: datetime

    class Config:
        from_attributes = True
