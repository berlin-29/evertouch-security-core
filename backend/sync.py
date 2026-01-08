# app/schemas/sync.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class SyncChangesResponse(BaseModel):
    server_time: datetime
    profile_updated: Optional[bool] = False
    pools_updated: Optional[bool] = False
    connections_updated: Optional[bool] = False
    incoming_payloads_updated: Optional[bool] = False
    link_cards_updated: Optional[bool] = False
