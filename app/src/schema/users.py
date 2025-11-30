from enum import Enum
from typing import Union
from pydantic import BaseModel


class UserTypeEnum(str, Enum):
    patron = "patron"
    librarian = "librarian"
    admin = "admin"

AdminRoleList = [UserTypeEnum.librarian, UserTypeEnum.admin]

class User(BaseModel):
    id: Union[int, None] = None
    type: UserTypeEnum = UserTypeEnum.patron
    name: str
    email: Union[str, None] = None
    member_id: Union[int, None] = None
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    is_active: Union[bool, None] = None
    username: str
    password: str


class UserUpdate(BaseModel):
    """Schema for updating user information - all fields optional"""
    type: Union[UserTypeEnum, None] = None
    name: Union[str, None] = None
    email: Union[str, None] = None
    member_id: Union[int, None] = None
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    is_active: Union[bool, None] = None
    username: Union[str, None] = None
    password: Union[str, None] = None


class UserProfileUpdate(BaseModel):
    """Schema for users updating their own profile - excludes sensitive fields"""
    name: Union[str, None] = None
    email: Union[str, None] = None
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    username: Union[str, None] = None
    password: Union[str, None] = None


class ActivateUserRequest(BaseModel):
    email: Union[str, None] = None
    phone_number: Union[str, None] = None
    username: Union[str, None] = None
