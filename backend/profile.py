# app/schemas/profile.py
from pydantic import BaseModel
from datetime import datetime
from uuid import UUID
from typing import Optional

class ProfileFieldBase(BaseModel):
    field_id: str
    ciphertext: str # base64

class ProfileFieldCreate(ProfileFieldBase):
    pass

class ProfileFieldResponse(ProfileFieldBase):
    id: UUID
    user_id: UUID
    updated_at: datetime

    class Config:
        from_attributes = True

class ProfileUpdate(BaseModel):
    profile_fields: list[ProfileFieldCreate]

class PublicProfileUpdate(BaseModel):
    public_display_name: Optional[str] = None
    public_headline: Optional[str] = None
    public_evertouch_id: Optional[str] = None
    device_token: Optional[str] = None
    locale: Optional[str] = None

class DeviceTokenUpdate(BaseModel):
    device_token: Optional[str] = None
    locale: Optional[str] = None
