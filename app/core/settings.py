from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Maktaba API"
    db_endpoint: str
    db_user: str
    db_pw: str
    db_port: str
    db_name: str
    secret_key: str
    access_token_expire_minutes: str = "30"
    algorithm: str = "HS256"
    db_url: str
    test_db_url: str
    image_api_key: str
    google_cxe: str
    s3_keyid: str
    s3_secret: str
    supabase_url: str
    supabase_key: str
    supabase_service_key: str
    stripe_api_key: str
    stripe_api_live_key: str
    stripe_webhook_secret: str = ""  # Optional for local development

    # Refresh token configuration
    refresh_token_expire_days: int = 30
    refresh_token_remember_me_days: int = 90

    # Environment configuration
    environment: str = "development"  # development, staging, or production

    # SMTP configuration
    smtp_host: str = "smtp-relay.brevo.com"
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "noreply@maktabadev.com"
    
    frontend_url: str = "http://localhost:5173"
    
    # Password Policy Configuration
    password_min_length: int = 8
    password_max_length: int = 128
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special_chars: bool = True
    password_special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    password_prevent_common_passwords: bool = True
    password_prevent_personal_info: bool = True
    password_history_count: int = 5  # Prevent reusing last N passwords
    password_max_age_days: int = 90  # Force password change after N days
    password_warn_expiry_days: int = 7  # Warn user N days before expiry
    
    # Account Lockout Policy
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    lockout_escalation_enabled: bool = True  # Increase lockout time for repeated violations
    lockout_notify_user: bool = True  # Send notification email on lockout
    
    # Rate Limiting Configuration
    rate_limit_enabled: bool = True
    
    # Authentication endpoint rate limits (per IP)
    LOGIN_RATE_LIMIT_PER_IP: int = 5  # Login attempts per IP
    LOGIN_RATE_LIMIT_WINDOW: int = 300  # 5 minutes in seconds
    
    REGISTER_RATE_LIMIT_PER_IP: int = 3  # Registration attempts per IP
    REGISTER_RATE_LIMIT_WINDOW: int = 3600  # 1 hour in seconds
    
    PASSWORD_RESET_RATE_LIMIT_PER_IP: int = 3  # Password reset requests per IP
    PASSWORD_RESET_RATE_LIMIT_WINDOW: int = 3600  # 1 hour in seconds
    
    PASSWORD_CHANGE_RATE_LIMIT_PER_IP: int = 5  # Password change attempts per IP
    PASSWORD_CHANGE_RATE_LIMIT_WINDOW: int = 900  # 15 minutes in seconds
    
    DEFAULT_AUTH_RATE_LIMIT_PER_IP: int = 10  # Default auth attempts per IP
    DEFAULT_AUTH_RATE_LIMIT_WINDOW: int = 600  # 10 minutes in seconds
    
    # User-based rate limits (authenticated users)
    USER_RATE_LIMIT_PER_USER: int = 100  # Requests per user
    USER_RATE_LIMIT_WINDOW: int = 3600  # 1 hour in seconds
    
    # Redis URL for distributed rate limiting (optional)
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Session Security
    session_timeout_minutes: int = 30  # Auto-logout after inactivity
    max_concurrent_sessions: int = 5  # Max sessions per user
    require_fresh_auth_for_sensitive: bool = True  # Require recent auth for sensitive actions
    fresh_auth_timeout_minutes: int = 10  # How recent auth must be for sensitive actions
    
    # Security Headers
    security_headers_enabled: bool = True
    hsts_max_age_seconds: int = 31536000  # 1 year
    csp_enabled: bool = True
    csp_policy: str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'"
    
    # Audit Logging
    audit_log_enabled: bool = True
    audit_log_auth_events: bool = True
    audit_log_admin_actions: bool = True
    audit_log_password_changes: bool = True
    audit_log_suspicious_activity: bool = True
    audit_log_retention_days: int = 365
    
    # Two-Factor Authentication (Future)
    totp_enabled: bool = False
    totp_issuer_name: str = "Maktaba"
    backup_codes_count: int = 10
    
    # Advanced Security Features
    ip_whitelist_enabled: bool = False
    ip_whitelist: list[str] = []
    suspicious_activity_detection: bool = True
    device_fingerprinting_enabled: bool = True
    
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
