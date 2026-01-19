from pydantic import BaseModel
from uuid import UUID

class WalletPassRequest(BaseModel):
    share_id: UUID
    qr_content: str
    label: str | None = None
    description: str | None = None
    background_color: str | None = None
    foreground_color: str | None = None
