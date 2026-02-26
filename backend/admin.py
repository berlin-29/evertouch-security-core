from typing import List, Literal

from pydantic import BaseModel, EmailStr, Field


class RelaunchEmailRequest(BaseModel):
    emails: List[EmailStr] = Field(..., min_length=1)
    language: Literal["en", "de"] = "en"
    dry_run: bool = False
