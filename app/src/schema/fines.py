from datetime import datetime
from pydantic import BaseModel


class Fines(BaseModel):
    user_id: int
    id: int
    amount: float
    issued_date: datetime
    paid: bool
    catalog_item_id: int