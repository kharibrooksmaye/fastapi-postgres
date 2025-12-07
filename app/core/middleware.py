"""
FastAPI middleware for request/response logging and error handling.

This module provides comprehensive middleware for logging, error handling,
request tracing, and security monitoring across all API endpoints.
"""

import time
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.error_handling import (
    SecurityError,
    ValidationError as CustomValidationError,
    BusinessLogicError,
    APIException,
    create_error_response,
    handle_validation_error,
    handle_security_error,
    handle_database_error,
    log_exception,
    sanitize_error_details
)
from app.core.logging import (
    security_event_logger,
    performance_event_logger,
    app_logger,
    generate_request_id,
    get_client_ip
)
from app.core.settings import settings


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging and performance monitoring."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate unique request ID
        request_id = generate_request_id()
        request.state.request_id = request_id
        
        # Extract request context
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")
        method = request.method
        path = request.url.path
        
        # Log request start
        start_time = time.time()
        
        app_logger.info(
            f"Request started: {method} {path}",
            extra={
                "event_type": "request_start",
                "request_id": request_id,
                "method": method,
                "path": path,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "query_params": dict(request.query_params) if request.query_params else None
            }
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Log successful response
            performance_event_logger.log_request(
                method=method,
                endpoint=path,
                status_code=response.status_code,
                response_time=response_time,
                user_id=getattr(request.state, "user_id", None),
                client_ip=client_ip,
                request_id=request_id
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as exc:
            # Calculate response time for errors
            response_time = time.time() - start_time
            
            # Log exception
            log_exception(request, exc, {"response_time": response_time})
            
            # Re-raise to be handled by exception handlers
            raise


class ErrorHandlerMiddleware:
    """Centralized error handling middleware."""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.settings = settings
        self._register_exception_handlers()
    
    def _register_exception_handlers(self):
        """Register all exception handlers."""
        
        @self.app.exception_handler(SecurityError)
        async def security_error_handler(request: Request, exc: SecurityError):
            return handle_security_error(request, exc)
        
        @self.app.exception_handler(CustomValidationError)
        async def validation_error_handler(request: Request, exc: CustomValidationError):
            return create_error_response(
                request=request,
                status_code=exc.status_code,
                error=exc.detail,
                error_code="VALIDATION_ERROR",
                field_errors=exc.field_errors
            )
        
        @self.app.exception_handler(RequestValidationError)
        async def request_validation_error_handler(request: Request, exc: RequestValidationError):
            return handle_validation_error(request, exc.errors())
        
        @self.app.exception_handler(ValidationError)
        async def pydantic_validation_error_handler(request: Request, exc: ValidationError):
            return handle_validation_error(request, exc.errors())
        
        @self.app.exception_handler(BusinessLogicError)
        async def business_logic_error_handler(request: Request, exc: BusinessLogicError):
            return create_error_response(
                request=request,
                status_code=exc.status_code,
                error=exc.detail,
                error_code=exc.error_code,
                details=exc.context
            )
        
        @self.app.exception_handler(APIException)
        async def api_exception_handler(request: Request, exc: APIException):
            return create_error_response(
                request=request,
                status_code=exc.status_code,
                error=exc.detail,
                error_code=exc.error_code,
                details=exc.context
            )
        
        @self.app.exception_handler(StarletteHTTPException)
        async def http_exception_handler(request: Request, exc: StarletteHTTPException):
            return create_error_response(
                request=request,
                status_code=exc.status_code,
                error=exc.detail or "HTTP error occurred",
                error_code="HTTP_ERROR"
            )
        
        @self.app.exception_handler(Exception)
        async def general_exception_handler(request: Request, exc: Exception):
            # Log unexpected errors
            log_exception(
                request, 
                exc, 
                {"severity": "high", "unexpected": True}
            )
            
            # Handle database errors specifically
            if "database" in str(exc).lower() or "sql" in str(exc).lower():
                return handle_database_error(request, exc)
            
            # Return generic error for production
            error_details = sanitize_error_details(
                str(exc),
                is_production=getattr(self.settings, "ENVIRONMENT", "production") == "production"
            )
            
            return create_error_response(
                request=request,
                status_code=500,
                error="Internal server error",
                error_code="INTERNAL_ERROR",
                details=error_details if not getattr(self.settings, "ENVIRONMENT", "production") == "production" else None
            )


class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for security event logging."""
    
    def __init__(self, app, excluded_paths: list = None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or ["/health", "/metrics", "/docs", "/openapi.json"]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip logging for health checks and static assets
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        # Extract security context
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")
        request_id = getattr(request.state, "request_id", "unknown")
        
        # Check for suspicious patterns
        self._check_suspicious_patterns(request, client_ip, user_agent, request_id)
        
        try:
            response = await call_next(request)
            
            # Log authentication events
            if "auth" in request.url.path or "login" in request.url.path:
                self._log_auth_event(request, response, client_ip, user_agent, request_id)
            
            return response
            
        except Exception as exc:
            # Log security-related exceptions
            if isinstance(exc, SecurityError):
                security_event_logger.security_violation(
                    violation_type=exc.__class__.__name__,
                    details=str(exc),
                    client_ip=client_ip,
                    user_id=getattr(request.state, "user_id", None),
                    endpoint=request.url.path,
                    request_id=request_id,
                    severity="high"
                )
            raise
    
    def _check_suspicious_patterns(
        self, 
        request: Request, 
        client_ip: str, 
        user_agent: str, 
        request_id: str
    ):
        """Check for suspicious request patterns."""
        
        # Check for SQL injection patterns in URL
        suspicious_sql_patterns = [
            "union+select", "drop+table", "insert+into", "delete+from",
            "exec+", "xp_", "sp_", "0x", "char(", "waitfor+delay"
        ]
        
        url_lower = str(request.url).lower()
        for pattern in suspicious_sql_patterns:
            if pattern in url_lower:
                security_event_logger.security_violation(
                    violation_type="sql_injection_attempt",
                    details=f"Suspicious SQL pattern detected: {pattern}",
                    client_ip=client_ip,
                    user_id=None,
                    endpoint=request.url.path,
                    request_id=request_id,
                    severity="high"
                )
                break
        
        # Check for XSS patterns
        xss_patterns = ["<script", "javascript:", "onerror=", "onload="]
        for pattern in xss_patterns:
            if pattern in url_lower:
                security_event_logger.security_violation(
                    violation_type="xss_attempt",
                    details=f"Suspicious XSS pattern detected: {pattern}",
                    client_ip=client_ip,
                    user_id=None,
                    endpoint=request.url.path,
                    request_id=request_id,
                    severity="medium"
                )
                break
        
        # Check for suspicious user agents
        suspicious_agents = [
            "sqlmap", "nikto", "nmap", "masscan", "nessus",
            "burpsuite", "gobuster", "dirb", "wget", "curl"
        ]
        
        user_agent_lower = user_agent.lower()
        for agent in suspicious_agents:
            if agent in user_agent_lower:
                security_event_logger.security_violation(
                    violation_type="suspicious_user_agent",
                    details=f"Suspicious user agent detected: {user_agent}",
                    client_ip=client_ip,
                    user_id=None,
                    endpoint=request.url.path,
                    request_id=request_id,
                    severity="medium"
                )
                break
    
    def _log_auth_event(
        self, 
        request: Request, 
        response: Response, 
        client_ip: str, 
        user_agent: str, 
        request_id: str
    ):
        """Log authentication-related events."""
        
        if "login" in request.url.path:
            # This will be enhanced when we integrate with the auth system
            app_logger.info(
                "Authentication endpoint accessed",
                extra={
                    "event_type": "auth_endpoint_access",
                    "endpoint": request.url.path,
                    "method": request.method,
                    "status_code": response.status_code,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "request_id": request_id
                }
            )


def setup_middleware(app: FastAPI):
    """Setup all middleware for the application."""
    
    # Add middleware in reverse order (last added = first executed)
    
    # Error handling (should be last to catch all errors)
    ErrorHandlerMiddleware(app)
    
    # Security logging
    app.add_middleware(SecurityLoggingMiddleware)
    
    # Request logging and performance monitoring
    app.add_middleware(RequestLoggingMiddleware)
    
    app_logger.info("All middleware configured successfully")