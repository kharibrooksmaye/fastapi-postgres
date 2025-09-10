from enum import Enum
from typing import Union
from pydantic import BaseModel

class UserTypeEnum(str, Enum):
    patron = "patron"
    librarian = "librarian"
    admin = "admin"

class User(BaseModel):
    id: int
    type: UserTypeEnum = UserTypeEnum.patron
    name: str
    email: str
    member_id: int
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    is_active: Union[bool, None] = None