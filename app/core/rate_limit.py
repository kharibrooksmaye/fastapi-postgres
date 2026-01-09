"""
Rate limiting module for FastAPI application.

This module provides comprehensive rate limiting functionality specifically
designed for authentication endpoints to prevent brute force attacks and
abuse. Uses in-memory storage with Redis fallback support.

Key Features:
- Per-IP rate limiting for authentication endpoints
- Per-user rate limiting for authenticated operations
- Sliding window algorithm for accurate rate limiting
- Configurable limits based on endpoint type
- Enhanced security for sensitive operations
- Integration with authentication system
"""

import time
from typing import Dict, Any
from collections import defaultdict, deque
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.settings import settings
import logging

logger = logging.getLogger(__name__)

# In-memory rate limiting storage (for development/simple deployments)
_rate_limit_store: Dict[str, deque] = defaultdict(deque)


def get_rate_limit_key(request: Request, endpoint: str = "") -> str:
    """
    Generate rate limit key based on request and endpoint.
    
    Combines IP address with endpoint for granular rate limiting.
    """
    client_ip = get_remote_address(request)
    if endpoint:
        return f"rate_limit:{endpoint}:{client_ip}"
    return f"rate_limit:general:{client_ip}"


def get_user_rate_limit_key(user_id: int, endpoint: str = "") -> str:
    """Generate rate limit key for authenticated users."""
    if endpoint:
        return f"rate_limit:user:{endpoint}:{user_id}"
    return f"rate_limit:user:general:{user_id}"


# Rate limiter instance with fallback to in-memory storage
# Check if we're in testing mode - disable rate limiting for tests
import os
_testing_mode = os.environ.get('TESTING', '').lower() in ('1', 'true', 'yes')

if _testing_mode:
    # In testing mode, use very high limits that won't interfere with tests
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000000 per minute"],
        enabled=False  # Disable rate limiting entirely in tests
    )
    logger.info("Rate limiter disabled for testing mode")
elif settings.REDIS_URL:
    try:
        # Try to use Redis if URL is provided and available
        limiter = Limiter(
            key_func=get_remote_address,
            storage_uri=settings.REDIS_URL,
            default_limits=["1000 per day", "100 per hour"]
        )
        logger.info(f"Rate limiter initialized with Redis backend: {settings.REDIS_URL}")
    except Exception as e:
        # Fallback to in-memory storage if Redis connection fails
        logger.warning(f"Redis connection failed ({e}), falling back to in-memory rate limiting")
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["1000 per day", "100 per hour"]
        )
else:
    # Use in-memory storage by default
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per day", "100 per hour"]
    )
    logger.info("Rate limiter initialized with in-memory backend")


class CustomRateLimitExceeded(RateLimitExceeded):
    """Custom rate limit exception with enhanced error details."""
    
    def __init__(self, detail: str, retry_after: int = None):
        super().__init__(detail)
        self.retry_after = retry_after


async def rate_limit_exceeded_handler(request: Request, exc):
    """
    Custom handler for rate limit exceeded errors.
    
    Provides detailed error response with security headers.
    Handles both RateLimitExceeded and connection errors gracefully.
    """
    client_ip = get_remote_address(request)
    
    # Handle different types of exceptions
    if isinstance(exc, RateLimitExceeded):
        detail = getattr(exc, 'detail', 'Rate limit exceeded')
        logger.warning(f"Rate limit exceeded for {client_ip} on {request.url.path}")
    else:
        # Handle connection errors or other exceptions
        detail = "Rate limiting service temporarily unavailable"
        logger.error(f"Rate limiting error for {client_ip} on {request.url.path}: {exc}")
    
    # Extract retry-after from exception if available
    retry_after = getattr(exc, 'retry_after', 60)
    
    response = JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": "rate_limit_exceeded",
            "message": "Too many requests. Please try again later.",
            "detail": str(detail),
            "retry_after": retry_after
        }
    )
    
    # Add security headers
    response.headers["Retry-After"] = str(retry_after)
    response.headers["X-RateLimit-Limit"] = "Rate limit exceeded"
    response.headers["X-RateLimit-Remaining"] = "0"
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + retry_after)
    
    return response


class RateLimitManager:
    """
    In-memory rate limit manager for different endpoint types.
    
    Provides fine-grained control over rate limiting policies
    for different types of authentication operations using
    in-memory sliding window storage.
    """
    
    def __init__(self):
        self.store = _rate_limit_store
    
    def check_rate_limit(
        self, 
        key: str, 
        limit: int, 
        window: int,
        request: Request = None
    ) -> Dict[str, Any]:
        """
        Check if request is within rate limit using sliding window.
        
        Args:
            key: Unique identifier for rate limiting
            limit: Maximum number of requests allowed
            window: Time window in seconds
            request: FastAPI request object for logging
            
        Returns:
            Dict with rate limit status and metadata
        """
        try:
            current_time = time.time()
            
            # Get request queue for this key
            request_queue = self.store[key]
            
            # Clean old entries (sliding window)
            while request_queue and request_queue[0] <= current_time - window:
                request_queue.popleft()
            
            # Count current requests in window
            current_count = len(request_queue)
            
            if current_count >= limit:
                # Rate limit exceeded
                if request_queue:
                    oldest_request_time = request_queue[0]
                    reset_time = int(oldest_request_time + window)
                    retry_after = max(1, reset_time - int(current_time))
                else:
                    retry_after = window
                    reset_time = int(current_time + window)
                
                if request:
                    logger.warning(
                        f"Rate limit exceeded for key {key}: "
                        f"{current_count}/{limit} requests in {window}s window"
                    )
                
                return {
                    "allowed": False,
                    "current_count": current_count,
                    "limit": limit,
                    "window": window,
                    "retry_after": retry_after,
                    "reset_time": reset_time
                }
            
            # Add current request to window
            request_queue.append(current_time)
            
            return {
                "allowed": True,
                "current_count": current_count + 1,
                "limit": limit,
                "window": window,
                "remaining": limit - (current_count + 1),
                "reset_time": int(current_time + window)
            }
            
        except Exception as e:
            logger.error(f"Rate limit check failed for key {key}: {e}")
            # On error, allow request but log error
            return {
                "allowed": True,
                "current_count": 0,
                "limit": limit,
                "window": window,
                "error": str(e)
            }
    
    def check_authentication_rate_limit(
        self, 
        request: Request, 
        endpoint_type: str = "login"
    ) -> None:
        """
        Check rate limits for authentication endpoints.
        
        Raises HTTPException if rate limit is exceeded.
        """
        client_ip = get_remote_address(request)
        
        # Get rate limit settings based on endpoint type
        if endpoint_type == "login":
            limit = settings.LOGIN_RATE_LIMIT_PER_IP
            window = settings.LOGIN_RATE_LIMIT_WINDOW
        elif endpoint_type == "register":
            limit = settings.REGISTER_RATE_LIMIT_PER_IP
            window = settings.REGISTER_RATE_LIMIT_WINDOW
        elif endpoint_type == "password_reset":
            limit = settings.PASSWORD_RESET_RATE_LIMIT_PER_IP
            window = settings.PASSWORD_RESET_RATE_LIMIT_WINDOW
        elif endpoint_type == "password_change":
            limit = settings.PASSWORD_CHANGE_RATE_LIMIT_PER_IP
            window = settings.PASSWORD_CHANGE_RATE_LIMIT_WINDOW
        else:
            # Default rate limit
            limit = settings.DEFAULT_AUTH_RATE_LIMIT_PER_IP
            window = settings.DEFAULT_AUTH_RATE_LIMIT_WINDOW
        
        rate_limit_key = get_rate_limit_key(request, endpoint_type)
        result = self.check_rate_limit(rate_limit_key, limit, window, request)
        
        if not result["allowed"]:
            logger.warning(
                f"Rate limit exceeded for {client_ip} on {endpoint_type}: "
                f"{result['current_count']}/{result['limit']} requests"
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many {endpoint_type} attempts. Please try again later.",
                    "retry_after": result["retry_after"],
                    "limit": result["limit"],
                    "window": result["window"]
                }
            )
    
    def check_user_rate_limit(
        self, 
        user_id: int, 
        endpoint_type: str = "general",
        limit: int = None,
        window: int = None
    ) -> None:
        """
        Check rate limits for authenticated user operations.
        
        Raises HTTPException if rate limit is exceeded.
        """
        # Use provided limits or defaults
        if limit is None:
            limit = settings.USER_RATE_LIMIT_PER_USER
        if window is None:
            window = settings.USER_RATE_LIMIT_WINDOW
        
        rate_limit_key = get_user_rate_limit_key(user_id, endpoint_type)
        result = self.check_rate_limit(rate_limit_key, limit, window)
        
        if not result["allowed"]:
            logger.warning(
                f"User rate limit exceeded for user {user_id} on {endpoint_type}: "
                f"{result['current_count']}/{result['limit']} requests"
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "user_rate_limit_exceeded", 
                    "message": "Too many requests for this operation. Please try again later.",
                    "retry_after": result["retry_after"],
                    "limit": result["limit"],
                    "window": result["window"]
                }
            )


# Global rate limit manager instance
rate_limit_manager = RateLimitManager()


# Decorator for easy rate limiting
def rate_limit(endpoint_type: str = "general"):
    """
    Decorator to apply rate limiting to FastAPI endpoints.
    
    Usage:
        @rate_limit("login")
        async def login_endpoint(request: Request):
            ...
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Find request object in args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if request:
                rate_limit_manager.check_authentication_rate_limit(
                    request, endpoint_type
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Middleware setup functions
def setup_rate_limiting(app):
    """Setup rate limiting middleware for FastAPI app."""
    try:
        # Add SlowAPI middleware
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
        # Also handle connection errors that might occur with Redis
        app.add_exception_handler(ConnectionError, rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)
        
        logger.info("Rate limiting middleware configured successfully")
    except Exception as e:
        logger.error(f"Failed to setup rate limiting middleware: {e}")
        logger.info("Application will continue without rate limiting")


def cleanup_rate_limiting():
    """Cleanup rate limiting resources."""
    # Clear in-memory store
    _rate_limit_store.clear()
    logger.info("Rate limiting cleanup completed")