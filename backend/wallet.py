from pydantic import BaseModel
from uuid import UUID

class WalletPassRequest(BaseModel):
    share_id: UUID
    qr_content: str
    label: str | None = None
    description: str | None = None
    background_color: str | None = None
    foreground_color: str | None = None
    # Enhanced design fields
    first_name: str | None = None
    last_name: str | None = None
    pool_name: str | None = None
    email: str | None = None
    phone: str | None = None
    headline: str | None = None
    website: str | None = "https://evertouch.app"
