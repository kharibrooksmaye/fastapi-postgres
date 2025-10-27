from datetime import datetime
from decimal import Decimal

from sqlmodel import Field, SQLModel
from typing import Optional


class Fines(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    amount: Decimal
    issued_date: datetime = Field(default_factory=datetime.now())
    paid: bool = Field(default=False)
    catalog_item_id: int = Field(foreign_key="item.id")
    