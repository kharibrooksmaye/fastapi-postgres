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
    ON_HOLD = "on_hold"


class CatalogActionsEnum(str, Enum):
    CHECKOUT = "checkout"
    PLACE_HOLD = "place_hold"
    RENEW = "renew"
    RETURN = "return"


class CatalogEvent(BaseModel):
    action: str
    event_timestamp: datetime.datetime
    user: int
    catalog_id: int
    admin_id: Union[int, None] = None
    due_date: Union[datetime.date, None] = None
