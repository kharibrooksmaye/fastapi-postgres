from datetime import datetime
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
    created_at: Union[datetime, None] = None
    updated_at: Union[datetime, None] = None


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


# Password Management Schemas

class PasswordResetRequest(BaseModel):
    """Schema for requesting a password reset"""
    email: Union[str, None] = None
    username: Union[str, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class PasswordResetConfirm(BaseModel):
    """Schema for confirming password reset with token"""
    token: str
    new_password: str
    confirm_password: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "abc123def456...",
                "new_password": "NewSecurePassword123!",
                "confirm_password": "NewSecurePassword123!"
            }
        }


class PasswordChangeRequest(BaseModel):
    """Schema for changing password when authenticated"""
    current_password: str
    new_password: str
    confirm_password: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "current_password": "CurrentPassword123!",
                "new_password": "NewSecurePassword123!",
                "confirm_password": "NewSecurePassword123!"
            }
        }


class PasswordResetResponse(BaseModel):
    """Response schema for password reset request"""
    message: str
    success: bool
    user_status: Union[str, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "If an account with that email exists, a password reset link has been sent.",
                "success": True,
                "user_status": "active"
            }
        }


class PasswordChangeResponse(BaseModel):
    """Response schema for password change operations"""
    message: str
    success: bool
    password_changed_at: Union[datetime, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Password successfully changed",
                "success": True,
                "password_changed_at": "2025-11-30T19:30:00Z"
            }
        }


class AccountSecurityStatus(BaseModel):
    """Schema for account security status information"""
    is_locked: bool
    failed_login_attempts: int
    account_locked_until: Union[datetime, None] = None
    password_expires_at: Union[datetime, None] = None
    password_changed_at: Union[datetime, None] = None
    last_login_attempt: Union[datetime, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "is_locked": False,
                "failed_login_attempts": 0,
                "account_locked_until": None,
                "password_expires_at": "2026-02-28T19:30:00Z",
                "password_changed_at": "2025-11-30T19:30:00Z",
                "last_login_attempt": None
            }
        }


class UserWithSecurity(BaseModel):
    """Extended user schema including security information for admin views"""
    id: Union[int, None] = None
    type: UserTypeEnum = UserTypeEnum.patron
    name: str
    email: Union[str, None] = None
    member_id: Union[int, None] = None
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    is_active: Union[bool, None] = None
    username: str
    created_at: Union[datetime, None] = None
    updated_at: Union[datetime, None] = None
    security_status: Union[AccountSecurityStatus, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "type": "patron",
                "name": "John Doe",
                "email": "john@example.com",
                "member_id": 12345,
                "phone_number": "+1234567890",
                "address": "123 Main St",
                "is_active": True,
                "username": "johndoe",
                "created_at": "2025-11-30T19:30:00Z",
                "updated_at": "2025-11-30T19:30:00Z",
                "security_status": {
                    "is_locked": False,
                    "failed_login_attempts": 0,
                    "account_locked_until": None,
                    "password_expires_at": "2026-02-28T19:30:00Z",
                    "password_changed_at": "2025-11-30T19:30:00Z",
                    "last_login_attempt": None
                }
            }
        }
