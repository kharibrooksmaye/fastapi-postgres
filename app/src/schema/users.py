from typing import Union
from pydantic import BaseModel


class Patron(BaseModel):
    name: str
    email: str
    member_id: int
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    is_active: Union[bool, None] = None