# app/schemas/auth.py
from pydantic import BaseModel, EmailStr, field_validator
from uuid import UUID
from typing import Optional, List
from app.utils import validate_password_strength
from .profile import ProfileFieldCreate

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    public_key: str # base64
    encrypted_private_key_bundle: str # base64
    recovery_salt: str # base64
    
    # Optional public fields at signup
    public_display_name: Optional[str] = None
    public_headline: Optional[str] = None
    public_evertouch_id: Optional[str] = None

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str

class TokenRefresh(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    user_id: UUID
    email: EmailStr
    public_display_name: Optional[str] = None
    public_headline: Optional[str] = None
    public_evertouch_id: Optional[str] = None
    public_key: Optional[str] = None
    encrypted_private_key_bundle: Optional[str] = None
    recovery_salt: Optional[str] = None
    has_recovery_setup: bool = False
    
    class Config:
        from_attributes = True

class UserPublicResponse(BaseModel):
    user_id: UUID
    public_display_name: Optional[str] = None
    public_headline: Optional[str] = None
    public_evertouch_id: Optional[str] = None
    
    class Config:
        from_attributes = True

class UserWithTokens(UserResponse):
    access_token: str
    refresh_token: str
    public_key: Optional[str] = None
    encrypted_private_key_bundle: Optional[str] = None
    recovery_salt: Optional[str] = None

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):

    email: EmailStr

    code: str

    new_password: str

    new_public_key: str

    new_encrypted_private_key_bundle: str

    new_recovery_salt: str

    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)



# WebAuthn / Passkey Schemas

class WebAuthnOptions(BaseModel):

    options: dict # The actual options object from py-webauthn (JSON-serializable)

    session_id: str # To correlate the response



class WebAuthnRegistrationVerify(BaseModel):

    registration_response: dict

    session_id: str



class WebAuthnLoginVerify(BaseModel):

    authentication_response: dict

    session_id: str

    email: Optional[EmailStr] = None # Optional if we use user_id from session

class SaltResponse(BaseModel):
    salt: str

class HashMigration(BaseModel):
    new_auth_key: str
    public_key: Optional[str] = None
    encrypted_private_key_bundle: Optional[str] = None
    recovery_salt: Optional[str] = None

    @field_validator('new_auth_key')
    @classmethod
    def validate_key_format(cls, v: str) -> str:
        # Auth key should be a base64 string or hex, length check etc.
        # For now just ensure it's not empty
        if not v:
            raise ValueError('Auth key cannot be empty')
        return v

class KDFMigration(BaseModel):
    new_auth_key: str
    new_encrypted_private_key_bundle: str
    public_key: Optional[str] = None
    profile_fields: Optional[list[ProfileFieldCreate]] = None

class RecoverySetup(BaseModel):
    encrypted_recovery_bundle: str # Private key encrypted by Recovery Phrase key
    recovery_phrase_verification_hash: str # Hash of the Recovery Phrase for verification

class RecoveryInitiate(BaseModel):
    email: EmailStr

class RecoveryInitiateResponse(BaseModel):
    encrypted_recovery_bundle: str
    recovery_salt: str

class PasswordResetWithRecovery(BaseModel):
    email: EmailStr
    recovery_phrase_verification_hash: str # To verify before allowing reset
    new_auth_key: str
    new_encrypted_private_key_bundle: str
    new_encrypted_recovery_bundle: Optional[str] = None
    
class AccountDeletionRequest(BaseModel):
    password: str
