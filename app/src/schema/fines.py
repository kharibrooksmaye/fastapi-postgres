from datetime import datetime
from decimal import Decimal
from typing import Optional
from pydantic import BaseModel

from app.src.models.items import Item


class UserPublic(BaseModel):
    """Public user data without sensitive fields"""
    id: int
    type: str
    name: str
    email: Optional[str] = None
    member_id: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True


class FineBase(BaseModel):
    """Base fine schema without relationships"""
    id: int
    user_id: int
    catalog_item_id: int
    amount: Decimal
    due_date: datetime
    issued_date: datetime
    paid: bool
    days_late: int


class FineWithItem(FineBase):
    """Fine schema with catalog item and user relationships"""
    catalog_item: Optional[Item] = None
    user: Optional[UserPublic] = None

    class Config:
        from_attributes = True


class FineCreate(BaseModel):
    """Schema for creating a new fine"""
    user_id: int
    catalog_item_id: int
    amount: Decimal
    due_date: datetime
    paid: bool = False
    days_late: int = 0


class FineUpdate(BaseModel):
    """Schema for updating a fine"""
    amount: Optional[Decimal] = None
    paid: Optional[bool] = None
    days_late: Optional[int] = None
