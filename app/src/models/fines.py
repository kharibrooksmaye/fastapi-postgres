from datetime import datetime
from decimal import Decimal

from sqlmodel import Field, Relationship, SQLModel
from typing import Optional

from app.src.models.items import Item

# TYPE_CHECKING to avoid circular imports
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.src.models.users import User


class Fines(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    catalog_item_id: int = Field(foreign_key="item.id")
    amount: Decimal
    due_date: datetime
    issued_date: datetime = Field(default_factory=datetime.now())
    paid: bool = Field(default=False)
    days_late: int = Field(default=0)
    payment_intent_id: Optional[str] = Field(default=None, index=True)

    # Relationships - automatically load related data
    catalog_item: Optional[Item] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[Fines.catalog_item_id]"}
    )
    user: Optional["User"] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[Fines.user_id]"}
    )
    