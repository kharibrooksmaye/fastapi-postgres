"""
Structured logging configuration with security event tracking.

This module provides comprehensive logging configuration for security events,
performance monitoring, and operational insights with proper log formatting
and security context preservation.
"""

import json
import logging
import logging.config
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pathlib import Path

from pythonjsonlogger import jsonlogger


class SecurityContextFilter(logging.Filter):
    """Add security context to log records."""
    
    def filter(self, record):
        # Add default security fields if not present
        if not hasattr(record, 'event_type'):
            record.event_type = 'application'
        if not hasattr(record, 'request_id'):
            record.request_id = None
        if not hasattr(record, 'user_id'):
            record.user_id = None
        if not hasattr(record, 'client_ip'):
            record.client_ip = None
        
        return True


class PerformanceContextFilter(logging.Filter):
    """Add performance monitoring context to log records."""
    
    def filter(self, record):
        # Add default performance fields
        if not hasattr(record, 'response_time'):
            record.response_time = None
        if not hasattr(record, 'status_code'):
            record.status_code = None
        if not hasattr(record, 'endpoint'):
            record.endpoint = None
            
        return True


class CustomJSONFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with security and performance context."""
    
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp in ISO format (timezone-aware)
        log_record['timestamp'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        # Add application context
        log_record['app_name'] = 'maktabi-api'
        log_record['environment'] = os.getenv('ENVIRONMENT', 'development')
        log_record['version'] = os.getenv('APP_VERSION', '1.0.0')
        
        # Ensure level is always present
        log_record['level'] = record.levelname
        
        # Add security context if available
        security_fields = [
            'event_type', 'user_id', 'client_ip', 'request_id', 
            'endpoint', 'method', 'user_agent', 'security_context'
        ]
        for field in security_fields:
            if hasattr(record, field) and getattr(record, field) is not None:
                log_record[field] = getattr(record, field)
        
        # Add performance context if available
        performance_fields = ['response_time', 'status_code', 'db_query_count', 'cache_hit']
        for field in performance_fields:
            if hasattr(record, field) and getattr(record, field) is not None:
                log_record[field] = getattr(record, field)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    enable_json: bool = True,
    enable_security_logs: bool = True
) -> None:
    """Setup comprehensive logging configuration."""
    
    # Create logs directory if it doesn't exist
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure formatters
    if enable_json:
        formatter = CustomJSONFormatter(
            fmt='%(timestamp)s %(level)s %(name)s %(message)s'
        )
    else:
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # Configure handlers
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SecurityContextFilter())
    console_handler.addFilter(PerformanceContextFilter())
    handlers.append(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SecurityContextFilter())
        file_handler.addFilter(PerformanceContextFilter())
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        handlers=handlers,
        force=True
    )
    
    # Configure specific loggers
    loggers_config = {
        'app': logging.getLogger('app'),
        'security': logging.getLogger('security'),
        'performance': logging.getLogger('performance'),
        'audit': logging.getLogger('audit'),
        'database': logging.getLogger('database'),
        'authentication': logging.getLogger('authentication')
    }
    
    for logger_name, logger in loggers_config.items():
        logger.setLevel(getattr(logging, log_level.upper()))
        logger.propagate = False
        
        for handler in handlers:
            logger.addHandler(handler)


# Initialize loggers
app_logger = logging.getLogger('app')
security_logger = logging.getLogger('security')
performance_logger = logging.getLogger('performance')
audit_logger = logging.getLogger('audit')
database_logger = logging.getLogger('database')
auth_logger = logging.getLogger('authentication')


class SecurityEventLogger:
    """Specialized logger for security events."""
    
    def __init__(self):
        self.logger = security_logger
    
    def login_attempt(
        self,
        user_id: Optional[str],
        email: str,
        success: bool,
        client_ip: str,
        user_agent: str,
        request_id: str,
        failure_reason: Optional[str] = None
    ):
        """Log login attempt with security context."""
        self.logger.info(
            "Login attempt",
            extra={
                'event_type': 'login_attempt',
                'user_id': user_id,
                'email': email,
                'success': success,
                'client_ip': client_ip,
                'user_agent': user_agent,
                'request_id': request_id,
                'failure_reason': failure_reason
            }
        )
    
    def password_reset_request(
        self,
        email: str,
        client_ip: str,
        user_agent: str,
        request_id: str,
        user_exists: bool
    ):
        """Log password reset request."""
        self.logger.info(
            "Password reset requested",
            extra={
                'event_type': 'password_reset_request',
                'email': email,
                'client_ip': client_ip,
                'user_agent': user_agent,
                'request_id': request_id,
                'user_exists': user_exists
            }
        )
    
    def account_lockout(
        self,
        user_id: str,
        email: str,
        failed_attempts: int,
        client_ip: str,
        request_id: str
    ):
        """Log account lockout event."""
        self.logger.warning(
            "Account locked due to failed login attempts",
            extra={
                'event_type': 'account_lockout',
                'user_id': user_id,
                'email': email,
                'failed_attempts': failed_attempts,
                'client_ip': client_ip,
                'request_id': request_id
            }
        )
    
    def rate_limit_exceeded(
        self,
        endpoint: str,
        client_ip: str,
        user_id: Optional[str],
        limit: int,
        window: int,
        request_id: str
    ):
        """Log rate limiting event."""
        self.logger.warning(
            "Rate limit exceeded",
            extra={
                'event_type': 'rate_limit_exceeded',
                'endpoint': endpoint,
                'client_ip': client_ip,
                'user_id': user_id,
                'limit': limit,
                'window': window,
                'request_id': request_id
            }
        )
    
    def file_upload_attempt(
        self,
        user_id: str,
        filename: str,
        file_size: int,
        content_type: str,
        success: bool,
        client_ip: str,
        request_id: str,
        failure_reason: Optional[str] = None
    ):
        """Log file upload attempt."""
        self.logger.info(
            "File upload attempt",
            extra={
                'event_type': 'file_upload',
                'user_id': user_id,
                'filename': filename,
                'file_size': file_size,
                'content_type': content_type,
                'success': success,
                'client_ip': client_ip,
                'request_id': request_id,
                'failure_reason': failure_reason
            }
        )
    
    def security_violation(
        self,
        violation_type: str,
        details: str,
        client_ip: str,
        user_id: Optional[str],
        endpoint: str,
        request_id: str,
        severity: str = "medium"
    ):
        """Log security violation."""
        log_level = {
            "low": self.logger.info,
            "medium": self.logger.warning,
            "high": self.logger.error,
            "critical": self.logger.critical
        }.get(severity, self.logger.warning)
        
        log_level(
            f"Security violation: {violation_type}",
            extra={
                'event_type': 'security_violation',
                'violation_type': violation_type,
                'details': details,
                'client_ip': client_ip,
                'user_id': user_id,
                'endpoint': endpoint,
                'request_id': request_id,
                'severity': severity
            }
        )


class PerformanceLogger:
    """Specialized logger for performance monitoring."""
    
    def __init__(self):
        self.logger = performance_logger
    
    def log_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        response_time: float,
        user_id: Optional[str],
        client_ip: str,
        request_id: str,
        db_query_count: Optional[int] = None,
        cache_hit: Optional[bool] = None
    ):
        """Log request performance metrics."""
        self.logger.info(
            f"{method} {endpoint} - {status_code} - {response_time:.3f}s",
            extra={
                'event_type': 'api_request',
                'method': method,
                'endpoint': endpoint,
                'status_code': status_code,
                'response_time': response_time,
                'user_id': user_id,
                'client_ip': client_ip,
                'request_id': request_id,
                'db_query_count': db_query_count,
                'cache_hit': cache_hit
            }
        )
    
    def log_slow_query(
        self,
        query_type: str,
        execution_time: float,
        query_hash: str,
        request_id: str,
        threshold: float = 1.0
    ):
        """Log slow database queries."""
        if execution_time > threshold:
            self.logger.warning(
                f"Slow query detected: {query_type} took {execution_time:.3f}s",
                extra={
                    'event_type': 'slow_query',
                    'query_type': query_type,
                    'execution_time': execution_time,
                    'query_hash': query_hash,
                    'request_id': request_id,
                    'threshold': threshold
                }
            )


class AuditLogger:
    """Specialized logger for audit trails."""
    
    def __init__(self):
        self.logger = audit_logger
    
    def log_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        client_ip: str,
        request_id: str,
        success: bool = True
    ):
        """Log data access events."""
        self.logger.info(
            f"Data access: {action} {resource_type} {resource_id}",
            extra={
                'event_type': 'data_access',
                'user_id': user_id,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'action': action,
                'client_ip': client_ip,
                'request_id': request_id,
                'success': success
            }
        )
    
    def log_data_modification(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        changes: Dict[str, Any],
        client_ip: str,
        request_id: str
    ):
        """Log data modification events."""
        self.logger.info(
            f"Data modification: {action} {resource_type} {resource_id}",
            extra={
                'event_type': 'data_modification',
                'user_id': user_id,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'action': action,
                'changes': changes,
                'client_ip': client_ip,
                'request_id': request_id
            }
        )


# Initialize specialized loggers
security_event_logger = SecurityEventLogger()
performance_event_logger = PerformanceLogger()
audit_event_logger = AuditLogger()


def generate_request_id() -> str:
    """Generate unique request ID for tracing."""
    return str(uuid.uuid4())


def get_client_ip(request) -> str:
    """Extract client IP from request with proxy support."""
    # Check for X-Forwarded-For header (load balancers/proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()
    
    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct client IP
    return getattr(request.client, "host", "unknown")


# Initialize logging on module import
log_level = os.getenv("LOG_LEVEL", "INFO")
log_file = os.getenv("LOG_FILE")
enable_json = os.getenv("LOG_FORMAT", "json").lower() == "json"

setup_logging(
    log_level=log_level,
    log_file=log_file,
    enable_json=enable_json
)
