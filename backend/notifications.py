from pydantic import BaseModel
from typing import List


class ProfileUpdateNotificationRequest(BaseModel):
    changed_fields: List[str]
    pool_id: str
