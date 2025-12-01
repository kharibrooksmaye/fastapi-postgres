from datetime import datetime
from typing import Union
from pydantic import BaseModel, Field


# Authentication Schemas

class LoginRequest(BaseModel):
    """Schema for user login requests"""
    username: str = Field(..., min_length=1, description="Username or email")
    password: str = Field(..., min_length=1, description="User password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "password": "SecurePassword123!"
            }
        }


class LoginResponse(BaseModel):
    """Schema for successful login responses"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: dict
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "def456abc789...",
                "token_type": "bearer",
                "expires_in": 14400,
                "user_info": {
                    "id": 1,
                    "username": "johndoe",
                    "name": "John Doe",
                    "type": "patron",
                    "is_active": True
                }
            }
        }


class TokenRefreshRequest(BaseModel):
    """Schema for token refresh requests"""
    refresh_token: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "def456abc789..."
            }
        }


class TokenRefreshResponse(BaseModel):
    """Schema for token refresh responses"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 14400
            }
        }


class ActivationRequest(BaseModel):
    """Schema for user activation requests"""
    token: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "abc123def456..."
            }
        }


class ActivationResponse(BaseModel):
    """Schema for activation responses"""
    message: str
    success: bool
    user_id: Union[int, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Account successfully activated",
                "success": True,
                "user_id": 1
            }
        }


# Password Management Schemas (duplicated from users.py for auth module convenience)

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
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")
    confirm_password: str = Field(..., min_length=8, description="Confirm new password")
    
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
    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")
    confirm_password: str = Field(..., min_length=8, description="Confirm new password")
    
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
    requires_reauth: bool = False
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Password successfully changed",
                "success": True,
                "password_changed_at": "2025-11-30T19:30:00Z",
                "requires_reauth": False
            }
        }


# Security and Status Schemas

class SecurityStatusResponse(BaseModel):
    """Schema for security status check responses"""
    is_locked: bool
    lockout_expires_at: Union[datetime, None] = None
    failed_attempts: int
    max_attempts: int = 5
    password_expires_at: Union[datetime, None] = None
    password_age_days: Union[int, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "is_locked": False,
                "lockout_expires_at": None,
                "failed_attempts": 0,
                "max_attempts": 5,
                "password_expires_at": "2026-02-28T19:30:00Z",
                "password_age_days": 30
            }
        }


class AuthErrorResponse(BaseModel):
    """Schema for authentication error responses"""
    detail: str
    error_code: str
    user_status: Union[str, None] = None
    action_required: Union[str, None] = None
    retry_after: Union[int, None] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Invalid username or password",
                "error_code": "INVALID_CREDENTIALS",
                "user_status": "active",
                "action_required": None,
                "retry_after": None
            }
        }


class LogoutResponse(BaseModel):
    """Schema for logout responses"""
    message: str
    success: bool
    logged_out_at: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Successfully logged out",
                "success": True,
                "logged_out_at": "2025-11-30T19:30:00Z"
            }
        }