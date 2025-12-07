"""
Centralized input validation and security utilities.

This module provides standardized validation patterns, sanitization functions,
and security utilities to prevent injection attacks and ensure data integrity
across all API endpoints.
"""

import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator
from fastapi import HTTPException


class SecurityValidationError(HTTPException):
    """Custom exception for security validation failures."""
    
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail)


class BaseSecureModel(BaseModel):
    """Base model with security-focused validation patterns."""
    
    class Config:
        # Prevent extra fields that could be used for injection
        extra = "forbid"
        # Strip whitespace from string fields
        str_strip_whitespace = True
        # Validate assignment (not just initialization)
        validate_assignment = True


class SecureStringField(str):
    """Secure string field with sanitization and validation."""
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
        
    @classmethod
    def validate(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Must be a string")
            
        # Remove null bytes and control characters
        sanitized = "".join(char for char in value if ord(char) >= 32 or char in "\n\r\t")
        
        # Prevent XSS attempts
        if any(pattern in sanitized.lower() for pattern in [
            "<script", "</script>", "javascript:", "vbscript:", 
            "onload=", "onerror=", "onclick=", "onmouseover="
        ]):
            raise SecurityValidationError("Potentially malicious content detected")
            
        return sanitized.strip()


class SecureEmailField(str):
    """Email field with comprehensive validation."""
    
    EMAIL_REGEX = re.compile(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    )
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
        
    @classmethod
    def validate(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Must be a string")
            
        value = value.strip().lower()
        
        # Length validation
        if len(value) > 254:  # RFC 5321 limit
            raise ValueError("Email too long (max 254 characters)")
            
        if len(value) < 3:
            raise ValueError("Email too short")
            
        # Format validation
        if not cls.EMAIL_REGEX.match(value):
            raise ValueError("Invalid email format")
            
        # Prevent common injection attempts
        if any(char in value for char in ['"', "'", "<", ">", "&"]):
            raise SecurityValidationError("Invalid characters in email")
            
        return value


class SecureUsernameField(str):
    """Username field with security validation."""
    
    USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
        
    @classmethod
    def validate(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Must be a string")
            
        value = value.strip()
        
        # Format and length validation
        if not cls.USERNAME_REGEX.match(value):
            raise ValueError(
                "Username must be 3-30 characters, alphanumeric, dots, hyphens, and underscores only"
            )
            
        # Prevent reserved usernames
        reserved = {
            "admin", "administrator", "root", "system", "api", "www", 
            "mail", "email", "user", "test", "guest", "anonymous"
        }
        if value.lower() in reserved:
            raise ValueError("Username is reserved")
            
        return value


class SecurePasswordField(str):
    """Password field with strength validation."""
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
        
    @classmethod
    def validate(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Must be a string")
            
        # Length validation
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters")
            
        if len(value) > 128:
            raise ValueError("Password too long (max 128 characters)")
            
        # Strength validation
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in value)
        
        strength_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if strength_score < 3:
            raise ValueError(
                "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters"
            )
            
        # Prevent common weak passwords
        weak_patterns = [
            "password", "123456", "qwerty", "abc123", "admin", 
            "letmein", "welcome", "monkey", "dragon"
        ]
        if any(pattern in value.lower() for pattern in weak_patterns):
            raise ValueError("Password contains common weak patterns")
            
        return value


class PaginationParams(BaseSecureModel):
    """Standardized pagination parameters with security limits."""
    
    page: int = Field(default=1, ge=1, le=1000, description="Page number")
    size: int = Field(default=20, ge=1, le=100, description="Page size")
    
    @field_validator('page', 'size')
    @classmethod
    def validate_positive(cls, value):
        if value <= 0:
            raise ValueError("Must be positive")
        return value


class SortParams(BaseSecureModel):
    """Standardized sorting parameters with whitelist validation."""
    
    sort_by: Optional[str] = Field(default=None, description="Field to sort by")
    order: Optional[str] = Field(default="asc", pattern="^(asc|desc)$", description="Sort order")
    
    @field_validator('sort_by')
    @classmethod
    def validate_sort_field(cls, value, info):
        if value is None:
            return value
            
        # Whitelist of allowed sort fields (must be defined per endpoint)
        # This prevents SQL injection through ORDER BY clauses
        allowed_fields = info.data.get('allowed_sort_fields', set())
        if allowed_fields and value not in allowed_fields:
            raise ValueError(f"Invalid sort field. Allowed: {', '.join(allowed_fields)}")
            
        return value


def sanitize_sql_identifier(identifier: str) -> str:
    """Sanitize SQL identifiers (table/column names) to prevent injection.
    
    Args:
        identifier: The SQL identifier to sanitize
        
    Returns:
        Sanitized identifier safe for SQL queries
        
    Raises:
        SecurityValidationError: If identifier contains dangerous patterns
    """
    if not isinstance(identifier, str):
        raise SecurityValidationError("Identifier must be a string")
        
    # Remove dangerous characters
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '', identifier)
    
    # Prevent empty or purely numeric identifiers
    if not sanitized or sanitized.isdigit():
        raise SecurityValidationError("Invalid SQL identifier")
        
    # Prevent SQL reserved words
    sql_reserved = {
        'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
        'union', 'where', 'order', 'group', 'having', 'join', 'from', 'into'
    }
    if sanitized.lower() in sql_reserved:
        raise SecurityValidationError("Identifier cannot be SQL reserved word")
        
    return sanitized[:64]  # Limit length


def validate_json_input(data: Any, max_depth: int = 10, max_keys: int = 100) -> Any:
    """Validate JSON input to prevent DoS attacks and injection.
    
    Args:
        data: JSON data to validate
        max_depth: Maximum nesting depth allowed
        max_keys: Maximum number of keys at any level
        
    Returns:
        Validated data
        
    Raises:
        SecurityValidationError: If validation fails
    """
    def _check_depth(obj, current_depth=0):
        if current_depth > max_depth:
            raise SecurityValidationError(f"JSON too deeply nested (max {max_depth})")
            
        if isinstance(obj, dict):
            if len(obj) > max_keys:
                raise SecurityValidationError(f"Too many keys in object (max {max_keys})")
            for value in obj.values():
                _check_depth(value, current_depth + 1)
                
        elif isinstance(obj, list):
            if len(obj) > max_keys:
                raise SecurityValidationError(f"Array too long (max {max_keys})")
            for item in obj:
                _check_depth(item, current_depth + 1)
                
    _check_depth(data)
    return data


def create_secure_filter_params(allowed_fields: set) -> type:
    """Create a dynamic Pydantic model for secure filtering.
    
    Args:
        allowed_fields: Set of allowed field names for filtering
        
    Returns:
        Pydantic model class for secure filtering
    """
    
    class SecureFilterParams(BaseSecureModel):
        filter_field: Optional[str] = Field(default=None, description="Field to filter by")
        filter_value: Optional[str] = Field(default=None, description="Filter value")
        
        @field_validator('filter_field')
        @classmethod
        def validate_filter_field(cls, value):
            if value is not None and value not in allowed_fields:
                raise ValueError(f"Invalid filter field. Allowed: {', '.join(allowed_fields)}")
            return value
            
        @field_validator('filter_value')
        @classmethod
        def validate_filter_value(cls, value):
            if value is not None:
                # Sanitize filter value
                return SecureStringField.validate(value)
            return value
            
    return SecureFilterParams


class InputSanitizer:
    """Centralized input sanitization utilities."""
    
    @staticmethod
    def clean_string(value: str, max_length: int = 1000) -> str:
        """Clean and validate string input."""
        if not isinstance(value, str):
            raise ValueError("Must be a string")
            
        # Remove null bytes and control characters
        cleaned = "".join(char for char in value if ord(char) >= 32 or char in "\n\r\t")
        
        # Limit length
        if len(cleaned) > max_length:
            raise ValueError(f"String too long (max {max_length})")
            
        return cleaned.strip()
        
    @staticmethod
    def clean_filename(filename: str) -> str:
        """Sanitize filename for safe storage."""
        if not isinstance(filename, str):
            raise ValueError("Filename must be a string")
            
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[^\w\-_.]', '_', filename)
        
        # Prevent empty filename or hidden files
        if not sanitized or sanitized.startswith('.'):
            raise ValueError("Invalid filename")
            
        # Limit length
        return sanitized[:255]
        
    @staticmethod
    def validate_id(value: Union[int, str]) -> int:
        """Validate and convert ID values."""
        if isinstance(value, str):
            if not value.isdigit():
                raise ValueError("ID must be numeric")
            value = int(value)
            
        if not isinstance(value, int) or value <= 0:
            raise ValueError("ID must be positive integer")
            
        if value > 2**31 - 1:  # PostgreSQL integer limit
            raise ValueError("ID too large")
            
        return value