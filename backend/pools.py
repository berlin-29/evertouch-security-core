# app/schemas/pools.py
from pydantic import BaseModel
from typing import List
from uuid import UUID
from datetime import datetime

class PoolBase(BaseModel):
    pool_id: str
    label: str
    visible_fields: List[str]

class PoolCreate(PoolBase):
    pass

class PoolResponse(PoolBase):
    id: UUID
    user_id: UUID
    created_at: datetime

    class Config:
        from_attributes = True

class PoolsUpdate(BaseModel):
    pools: List[PoolCreate]
