import datetime
from enum import Enum
from typing import Union

from pydantic import BaseModel


class CatalogStatusEnum(str, Enum):
    AVAILABLE = "available"
    CHECKED_OUT = "checked_out"
    IN_TRANSIT = "in_transit"
    LOST = "lost"
    READY = "ready"
    RENEWED = "renewed"
    RESERVED = "reserved"


class CatalogActionsEnum(str, Enum):
    CHECKOUT = "checkout"
    RESERVE = "reserve"
    RENEW = "renew"
    RETURN = "return"


class CatalogEvent(BaseModel):
    action: str
    event_timestamp: datetime.datetime
    user: int
    catalog_id: int
    admin_id: Union[int, None] = None
    due_date: Union[datetime.date, None] = None
