"""
Security headers middleware for FastAPI application.

This module provides comprehensive security headers to protect against
common web vulnerabilities including XSS, clickjacking, MIME sniffing,
and other security threats.

Key Features:
- HTTPS Strict Transport Security (HSTS)
- Content Security Policy (CSP)
- X-Frame-Options for clickjacking protection
- X-Content-Type-Options to prevent MIME sniffing
- X-XSS-Protection for legacy XSS protection
- Referrer-Policy for privacy protection
- Permissions-Policy for feature control
"""

from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.settings import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add comprehensive security headers to all responses.
    
    Implements OWASP recommended security headers for web application
    security hardening.
    """

    def __init__(self, app, **kwargs):
        super().__init__(app)
        self.hsts_max_age = kwargs.get('hsts_max_age', settings.hsts_max_age_seconds)
        self.csp_policy = kwargs.get('csp_policy', settings.csp_policy)
        self.enabled = kwargs.get('enabled', settings.security_headers_enabled)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and add security headers to response."""
        
        # Process the request
        response = await call_next(request)
        
        # Add security headers if enabled
        if self.enabled:
            self._add_security_headers(response, request)
        
        return response

    def _add_security_headers(self, response: Response, request: Request) -> None:
        """Add comprehensive security headers to the response."""
        
        # HTTPS Strict Transport Security (HSTS)
        # Forces HTTPS for future requests
        response.headers["Strict-Transport-Security"] = (
            f"max-age={self.hsts_max_age}; includeSubDomains; preload"
        )
        
        # Content Security Policy (CSP)
        # Prevents XSS and data injection attacks
        if settings.csp_enabled:
            response.headers["Content-Security-Policy"] = self.csp_policy
        
        # X-Frame-Options
        # Prevents clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"
        
        # X-Content-Type-Options
        # Prevents MIME sniffing attacks
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # X-XSS-Protection
        # Legacy XSS protection (for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy
        # Controls how much referrer information is shared
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions-Policy (formerly Feature-Policy)
        # Controls which browser features can be used
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )
        
        # Cross-Origin-Embedder-Policy
        # Enables cross-origin isolation
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        
        # Cross-Origin-Opener-Policy
        # Isolates browsing context
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        
        # Cross-Origin-Resource-Policy
        # Controls cross-origin resource sharing
        response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        
        # X-Permitted-Cross-Domain-Policies
        # Prevents Adobe Flash and PDF cross-domain requests
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        
        # Cache-Control for sensitive endpoints
        if self._is_sensitive_endpoint(request.url.path):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        # Security logging for monitoring
        logger.debug(f"Added security headers to {request.method} {request.url.path}")

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """
        Determine if the endpoint contains sensitive information.
        
        Sensitive endpoints should not be cached and require
        additional security headers.
        """
        sensitive_paths = [
            "/auth/",
            "/users/",
            "/admin/",
            "/password/",
            "/token/",
            "/refresh",
            "/logout"
        ]
        
        return any(sensitive_path in path for sensitive_path in sensitive_paths)


def setup_security_headers(app, **kwargs):
    """
    Setup security headers middleware for FastAPI app.
    
    Args:
        app: FastAPI application instance
        **kwargs: Configuration options for middleware
    """
    # Add security headers middleware
    app.add_middleware(SecurityHeadersMiddleware, **kwargs)
    
    logger.info("Security headers middleware configured successfully")
    logger.info(f"HSTS max-age: {kwargs.get('hsts_max_age', settings.hsts_max_age_seconds)}")
    logger.info(f"CSP enabled: {settings.csp_enabled}")
    logger.info(f"Security headers enabled: {settings.security_headers_enabled}")


# CSRF Protection Utilities
class CSRFConfig:
    """Configuration for CSRF protection."""
    
    def __init__(self):
        self.secret_key = settings.secret_key
        self.cookie_name = "csrftoken"
        self.header_name = "X-CSRFToken"
        self.cookie_secure = settings.environment == "production"
        self.cookie_samesite = "lax"
        self.cookie_httponly = True


def get_csrf_config() -> CSRFConfig:
    """Get CSRF configuration instance."""
    return CSRFConfig()


# Content Security Policy Builder
class CSPBuilder:
    """Builder for dynamic Content Security Policy headers."""
    
    def __init__(self):
        self.directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'"],
            "font-src": ["'self'"],
            "object-src": ["'none'"],
            "media-src": ["'self'"],
            "frame-src": ["'none'"],
            "child-src": ["'none'"],
            "worker-src": ["'none'"],
            "frame-ancestors": ["'none'"],
            "form-action": ["'self'"],
            "base-uri": ["'self'"],
            "upgrade-insecure-requests": []
        }
    
    def add_source(self, directive: str, source: str) -> 'CSPBuilder':
        """Add a source to a CSP directive."""
        if directive in self.directives:
            if source not in self.directives[directive]:
                self.directives[directive].append(source)
        return self
    
    def build(self) -> str:
        """Build the CSP header string."""
        csp_parts = []
        for directive, sources in self.directives.items():
            if sources:
                csp_parts.append(f"{directive} {' '.join(sources)}")
            else:
                csp_parts.append(directive)
        
        return "; ".join(csp_parts)


def build_csp_for_environment() -> str:
    """Build CSP header based on current environment."""
    builder = CSPBuilder()
    
    if settings.environment == "development":
        # More permissive CSP for development
        builder.add_source("connect-src", "ws:")
        builder.add_source("connect-src", "wss:")
        builder.add_source("script-src", "'unsafe-eval'")
    
    return builder.build()