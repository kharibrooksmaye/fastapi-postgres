"""
Centralized error handling and response management.

This module provides standardized error responses, exception handling,
and security-focused error management across all API endpoints.
"""

import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.core.logging import security_logger, app_logger


class SecurityError(HTTPException):
    """Security-related HTTP exception with enhanced logging."""
    
    def __init__(
        self,
        status_code: int,
        detail: str,
        security_context: Optional[Dict[str, Any]] = None,
        log_level: str = "warning"
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.security_context = security_context or {}
        self.log_level = log_level
        
        # Log security events immediately
        security_logger.log(
            level=getattr(security_logger, log_level.upper()),
            msg=f"Security violation: {detail}",
            extra={
                "event_type": "security_error",
                "status_code": status_code,
                "detail": detail,
                **self.security_context
            }
        )


class ValidationError(HTTPException):
    """Input validation error with detailed field information."""
    
    def __init__(
        self,
        detail: str,
        field_errors: Optional[Dict[str, List[str]]] = None,
        status_code: int = status.HTTP_422_UNPROCESSABLE_CONTENT
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.field_errors = field_errors or {}


class BusinessLogicError(HTTPException):
    """Business logic error with context."""
    
    def __init__(
        self,
        detail: str,
        error_code: Optional[str] = None,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_code = error_code
        self.context = context or {}


class StandardErrorResponse(BaseModel):
    """Standardized error response schema."""
    model_config = ConfigDict(ser_json_timedelta='iso8601')
    
    success: bool = False
    error: str
    detail: Optional[str] = None  # Alias for 'error' for FastAPI compatibility
    error_code: Optional[str] = None
    details: Optional[Union[str, Dict[str, Any]]] = None
    field_errors: Optional[Dict[str, List[str]]] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: Optional[str] = None
    
    def __init__(self, **data):
        super().__init__(**data)
        # Ensure detail mirrors error for FastAPI compatibility
        if self.detail is None:
            object.__setattr__(self, 'detail', self.error)


class StandardSuccessResponse(BaseModel):
    """Standardized success response schema."""
    model_config = ConfigDict(ser_json_timedelta='iso8601')
    
    success: bool = True
    message: str
    data: Optional[Union[Dict[str, Any], List[Any]]] = None
    meta: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: Optional[str] = None


def create_error_response(
    request: Request,
    status_code: int,
    error: str,
    error_code: Optional[str] = None,
    details: Optional[Union[str, Dict[str, Any]]] = None,
    field_errors: Optional[Dict[str, List[str]]] = None
) -> JSONResponse:
    """Create standardized error response."""
    
    request_id = getattr(request.state, "request_id", None)
    
    response_data = StandardErrorResponse(
        error=error,
        error_code=error_code,
        details=details,
        field_errors=field_errors,
        request_id=request_id
    )
    
    # Log error for monitoring
    app_logger.error(
        f"API Error: {error}",
        extra={
            "status_code": status_code,
            "error_code": error_code,
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "client_ip": getattr(request.client, "host", "unknown")
        }
    )
    
    return JSONResponse(
        status_code=status_code,
        content=response_data.model_dump(mode='json')
    )


def create_success_response(
    message: str,
    data: Optional[Union[Dict[str, Any], List[Any]]] = None,
    meta: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create standardized success response."""
    
    response = StandardSuccessResponse(
        message=message,
        data=data,
        meta=meta,
        request_id=request_id
    )
    
    return response.model_dump(mode='json')


def sanitize_error_details(
    error_details: Any,
    is_production: bool = True
) -> Union[str, Dict[str, Any]]:
    """Sanitize error details to prevent information leakage."""
    
    if not is_production:
        # Development mode - return full details
        return error_details
    
    # Production mode - sanitize sensitive information
    if isinstance(error_details, dict):
        sanitized = {}
        safe_keys = {
            "field", "code", "type", "message", "input", "ctx"
        }
        
        for key, value in error_details.items():
            if key.lower() in safe_keys:
                sanitized[key] = str(value)[:200]  # Limit length
        
        return sanitized
    
    elif isinstance(error_details, str):
        # Remove potentially sensitive patterns
        sensitive_patterns = [
            r'password["\s]*[:=]["\s]*[^"\s]+',
            r'token["\s]*[:=]["\s]*[^"\s]+',
            r'secret["\s]*[:=]["\s]*[^"\s]+',
            r'key["\s]*[:=]["\s]*[^"\s]+'
        ]
        
        sanitized = error_details
        for pattern in sensitive_patterns:
            import re
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        
        return sanitized[:500]  # Limit length
    
    return "Internal server error"


class ErrorCategory:
    """Error categorization for monitoring and alerting."""
    
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    BUSINESS_LOGIC = "business_logic"
    SECURITY = "security"
    DATABASE = "database"
    EXTERNAL_SERVICE = "external_service"
    INTERNAL = "internal"


def categorize_exception(exception: Exception) -> str:
    """Categorize exception for monitoring purposes."""
    
    exception_name = exception.__class__.__name__.lower()
    
    if isinstance(exception, SecurityError):
        return ErrorCategory.SECURITY
    elif isinstance(exception, ValidationError):
        return ErrorCategory.VALIDATION
    elif isinstance(exception, BusinessLogicError):
        return ErrorCategory.BUSINESS_LOGIC
    elif "auth" in exception_name or "permission" in exception_name:
        return ErrorCategory.AUTHENTICATION
    elif "validation" in exception_name or "pydantic" in exception_name:
        return ErrorCategory.VALIDATION
    elif "database" in exception_name or "sql" in exception_name:
        return ErrorCategory.DATABASE
    elif "connection" in exception_name or "timeout" in exception_name:
        return ErrorCategory.EXTERNAL_SERVICE
    else:
        return ErrorCategory.INTERNAL


def log_exception(
    request: Request,
    exception: Exception,
    context: Optional[Dict[str, Any]] = None
):
    """Log exception with security and operational context."""
    
    error_category = categorize_exception(exception)
    request_id = getattr(request.state, "request_id", None)
    
    log_context = {
        "error_category": error_category,
        "exception_type": exception.__class__.__name__,
        "request_id": request_id,
        "path": request.url.path,
        "method": request.method,
        "client_ip": getattr(request.client, "host", "unknown"),
        "user_agent": request.headers.get("user-agent", "unknown"),
        **(context or {})
    }
    
    # Log at appropriate level based on category
    if error_category == ErrorCategory.SECURITY:
        security_logger.error(
            f"Security exception: {str(exception)}",
            extra=log_context
        )
    elif error_category in [ErrorCategory.DATABASE, ErrorCategory.INTERNAL]:
        app_logger.error(
            f"System exception: {str(exception)}",
            extra=log_context,
            exc_info=True  # Include stack trace
        )
    else:
        app_logger.warning(
            f"Application exception: {str(exception)}",
            extra=log_context
        )


def handle_validation_error(
    request: Request,
    validation_errors: List[Dict[str, Any]]
) -> JSONResponse:
    """Handle Pydantic validation errors with detailed field information."""
    
    field_errors = {}
    for error in validation_errors:
        field = ".".join(str(loc) for loc in error.get("loc", []))
        message = error.get("msg", "Invalid value")
        
        if field not in field_errors:
            field_errors[field] = []
        field_errors[field].append(message)
    
    return create_error_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        error="Validation failed",
        error_code="VALIDATION_ERROR",
        field_errors=field_errors
    )


def handle_security_error(
    request: Request,
    security_error: SecurityError
) -> JSONResponse:
    """Handle security errors with appropriate response and logging."""
    
    # Additional security logging
    security_logger.error(
        f"Security violation detected: {security_error.detail}",
        extra={
            "event_type": "security_violation",
            "status_code": security_error.status_code,
            "path": request.url.path,
            "method": request.method,
            "client_ip": getattr(request.client, "host", "unknown"),
            "user_agent": request.headers.get("user-agent", "unknown"),
            **security_error.security_context
        }
    )
    
    # Return sanitized error response
    return create_error_response(
        request=request,
        status_code=security_error.status_code,
        error="Security validation failed",
        error_code="SECURITY_ERROR",
        details=sanitize_error_details(security_error.detail)
    )


def handle_database_error(
    request: Request,
    db_error: Exception
) -> JSONResponse:
    """Handle database errors with appropriate logging and user-friendly messages."""
    
    # Log full error for debugging
    app_logger.error(
        f"Database error: {str(db_error)}",
        extra={
            "error_category": ErrorCategory.DATABASE,
            "request_id": getattr(request.state, "request_id", None),
            "path": request.url.path,
            "method": request.method,
        },
        exc_info=True
    )
    
    # Return user-friendly error
    return create_error_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error="A database error occurred",
        error_code="DATABASE_ERROR",
        details="Please try again later"
    )


def handle_rate_limit_error(
    request: Request,
    rate_limit_info: Dict[str, Any]
) -> JSONResponse:
    """Handle rate limiting errors with retry information."""
    
    return create_error_response(
        request=request,
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        error="Rate limit exceeded",
        error_code="RATE_LIMIT_EXCEEDED",
        details={
            "retry_after": rate_limit_info.get("retry_after"),
            "limit": rate_limit_info.get("limit"),
            "reset_time": rate_limit_info.get("reset_time")
        }
    )


class APIException(HTTPException):
    """Base API exception with enhanced error handling."""
    
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_code = error_code
        self.context = context or {}


# Pre-defined common errors
class NotFoundError(APIException):
    def __init__(self, resource: str, identifier: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} not found",
            error_code="RESOURCE_NOT_FOUND",
            context={"resource": resource, "identifier": identifier}
        )


class UnauthorizedError(APIException):
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="UNAUTHORIZED"
        )


class ForbiddenError(APIException):
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            error_code="FORBIDDEN"
        )


class ConflictError(APIException):
    def __init__(self, detail: str, resource: Optional[str] = None):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
            error_code="CONFLICT",
            context={"resource": resource} if resource else {}
        )