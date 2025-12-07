"""
Standardized and secure API schema models.

This module provides consistent, security-focused Pydantic models
for all API endpoints with comprehensive input validation.
"""

from datetime import datetime
from typing import List, Optional, Union
from pydantic import BaseModel, Field, field_validator

from app.core.validation import (
    BaseSecureModel,
    SecureStringField,
    SecureEmailField,
    SecureUsernameField,
    SecurePasswordField,
    PaginationParams,
    SortParams,
    InputSanitizer
)


# Authentication Schemas
class UserLoginRequest(BaseSecureModel):
    """Secure user login request schema."""
    
    email: SecureEmailField = Field(..., description="User email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")
    remember_me: Optional[bool] = Field(default=False, description="Remember login session")


class UserRegistrationRequest(BaseSecureModel):
    """Secure user registration request schema."""
    
    email: SecureEmailField = Field(..., description="User email address")
    username: SecureUsernameField = Field(..., description="Unique username")
    password: SecurePasswordField = Field(..., description="Strong password")
    confirm_password: str = Field(..., description="Password confirmation")
    first_name: SecureStringField = Field(..., min_length=1, max_length=100, description="First name")
    last_name: SecureStringField = Field(..., min_length=1, max_length=100, description="Last name")
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, confirm_password, info):
        password = info.data.get('password')
        if password and confirm_password != password:
            raise ValueError("Passwords do not match")
        return confirm_password


class PasswordResetRequest(BaseSecureModel):
    """Password reset request schema."""
    
    email: SecureEmailField = Field(..., description="User email address")


class PasswordResetConfirm(BaseSecureModel):
    """Password reset confirmation schema."""
    
    token: SecureStringField = Field(..., min_length=32, max_length=128, description="Reset token")
    new_password: SecurePasswordField = Field(..., description="New strong password")
    confirm_password: str = Field(..., description="Password confirmation")
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, confirm_password, info):
        password = info.data.get('new_password')
        if password and confirm_password != password:
            raise ValueError("Passwords do not match")
        return confirm_password


class PasswordChangeRequest(BaseSecureModel):
    """Password change request schema."""
    
    current_password: str = Field(..., min_length=1, max_length=128, description="Current password")
    new_password: SecurePasswordField = Field(..., description="New strong password")
    confirm_password: str = Field(..., description="Password confirmation")
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, confirm_password, info):
        password = info.data.get('new_password')
        if password and confirm_password != password:
            raise ValueError("Passwords do not match")
        return confirm_password


# User Management Schemas
class UserProfileUpdate(BaseSecureModel):
    """User profile update schema."""
    
    first_name: Optional[SecureStringField] = Field(None, min_length=1, max_length=100)
    last_name: Optional[SecureStringField] = Field(None, min_length=1, max_length=100)
    bio: Optional[SecureStringField] = Field(None, max_length=500, description="User biography")
    
    @field_validator('bio')
    @classmethod
    def validate_bio(cls, value):
        if value:
            return InputSanitizer.clean_string(value, max_length=500)
        return value


class UserResponse(BaseSecureModel):
    """Secure user response schema."""
    
    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


# Item Management Schemas
class ItemCreateRequest(BaseSecureModel):
    """Secure item creation request schema."""
    
    title: SecureStringField = Field(..., min_length=1, max_length=200, description="Item title")
    author: Optional[SecureStringField] = Field(None, max_length=100, description="Item author")
    description: Optional[SecureStringField] = Field(None, max_length=1000, description="Item description")
    isbn: Optional[str] = Field(None, pattern=r'^[0-9\-X]{10,17}$', description="ISBN number")
    category: Optional[SecureStringField] = Field(None, max_length=50, description="Item category")
    
    @field_validator('isbn')
    @classmethod
    def validate_isbn(cls, value):
        if value:
            # Remove hyphens and validate ISBN format
            cleaned = value.replace('-', '')
            if not (len(cleaned) in [10, 13] and (cleaned[:-1].isdigit() and cleaned[-1] in '0123456789X')):
                raise ValueError("Invalid ISBN format")
        return value
        
    @field_validator('description')
    @classmethod
    def validate_description(cls, value):
        if value:
            return InputSanitizer.clean_string(value, max_length=1000)
        return value


class ItemUpdateRequest(BaseSecureModel):
    """Secure item update request schema."""
    
    title: Optional[SecureStringField] = Field(None, min_length=1, max_length=200)
    author: Optional[SecureStringField] = Field(None, max_length=100)
    description: Optional[SecureStringField] = Field(None, max_length=1000)
    isbn: Optional[str] = Field(None, pattern=r'^[0-9\-X]{10,17}$')
    category: Optional[SecureStringField] = Field(None, max_length=50)
    is_available: Optional[bool] = None
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, value):
        if value:
            return InputSanitizer.clean_string(value, max_length=1000)
        return value


class ItemResponse(BaseSecureModel):
    """Secure item response schema."""
    
    id: int
    title: str
    author: Optional[str]
    description: Optional[str]
    isbn: Optional[str]
    category: Optional[str]
    is_available: bool
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


# Query Parameter Schemas
class ItemFilterParams(BaseSecureModel):
    """Secure item filtering parameters."""
    
    title: Optional[SecureStringField] = Field(None, max_length=200, description="Filter by title")
    author: Optional[SecureStringField] = Field(None, max_length=100, description="Filter by author")
    category: Optional[SecureStringField] = Field(None, max_length=50, description="Filter by category")
    is_available: Optional[bool] = Field(None, description="Filter by availability")
    
    # Pagination
    page: int = Field(default=1, ge=1, le=1000, description="Page number")
    size: int = Field(default=20, ge=1, le=100, description="Items per page")
    
    # Sorting with whitelist validation
    sort_by: Optional[str] = Field(default=None, description="Sort field")
    order: Optional[str] = Field(default="asc", pattern="^(asc|desc)$", description="Sort order")
    
    @field_validator('sort_by')
    @classmethod
    def validate_sort_field(cls, value):
        allowed_sort_fields = {'title', 'author', 'created_at', 'updated_at', 'category'}
        if value and value not in allowed_sort_fields:
            raise ValueError(f"Invalid sort field. Allowed: {', '.join(allowed_sort_fields)}")
        return value


class UserFilterParams(BaseSecureModel):
    """Secure user filtering parameters."""
    
    username: Optional[SecureStringField] = Field(None, max_length=30, description="Filter by username")
    email: Optional[SecureEmailField] = Field(None, description="Filter by email")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    is_verified: Optional[bool] = Field(None, description="Filter by verification status")
    
    # Pagination
    page: int = Field(default=1, ge=1, le=1000, description="Page number")
    size: int = Field(default=20, ge=1, le=50, description="Users per page")  # Smaller page size for user data
    
    # Sorting
    sort_by: Optional[str] = Field(default=None, description="Sort field")
    order: Optional[str] = Field(default="asc", pattern="^(asc|desc)$", description="Sort order")
    
    @field_validator('sort_by')
    @classmethod
    def validate_sort_field(cls, value):
        allowed_sort_fields = {'username', 'email', 'created_at', 'first_name', 'last_name'}
        if value and value not in allowed_sort_fields:
            raise ValueError(f"Invalid sort field. Allowed: {', '.join(allowed_sort_fields)}")
        return value


# File Upload Schemas
class FileUploadResponse(BaseSecureModel):
    """Secure file upload response schema."""
    
    status: int
    message: str
    url: str
    filename: str
    original_filename: str
    size: int
    content_type: str
    upload_timestamp: datetime = Field(default_factory=datetime.utcnow)


# Generic Response Schemas
class StandardResponse(BaseSecureModel):
    """Standard API response schema."""
    
    success: bool
    message: str
    data: Optional[Union[dict, list]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseSecureModel):
    """Standard error response schema."""
    
    success: bool = False
    error: str
    details: Optional[str] = None
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PaginatedResponse(BaseSecureModel):
    """Paginated response schema."""
    
    items: List[Union[dict, BaseModel]]
    total: int
    page: int
    size: int
    pages: int
    has_next: bool
    has_prev: bool
    
    @field_validator('page', 'size', 'total', 'pages')
    @classmethod
    def validate_positive(cls, value):
        if value < 0:
            raise ValueError("Must be non-negative")
        return value


# Security Schemas
class SecurityStatusResponse(BaseSecureModel):
    """Security status response schema."""
    
    account_locked: bool
    failed_login_attempts: int
    last_login: Optional[datetime]
    password_last_changed: Optional[datetime]
    two_factor_enabled: bool = False
    security_score: int = Field(ge=0, le=100, description="Security score out of 100")


class RateLimitResponse(BaseSecureModel):
    """Rate limiting response schema."""
    
    limit: int
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None