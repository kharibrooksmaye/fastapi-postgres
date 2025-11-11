# Production-Ready Persistent Login Implementation Guide

## Overview

This document provides actionable recommendations for implementing persistent login ("remember me") functionality in the FastAPI PostgreSQL application. The current system uses stateless JWT authentication with no persistent login capabilities.

---

## Recommended Architecture: Hybrid JWT + Refresh Token Pattern

The most production-ready approach combines:
1. **Short-lived Access Tokens** (JWT) - 15-30 minutes
2. **Long-lived Refresh Tokens** - Stored in database - 7-30 days
3. **Device/Session Tracking** - Tie tokens to specific devices
4. **"Remember Me" Flag** - Extend refresh token expiry for trusted devices

### Architecture Benefits
- **Security**: Compromised access tokens expire quickly
- **User Experience**: No unnecessary re-login with refresh tokens
- **Control**: Server can revoke tokens immediately
- **Auditability**: Track login devices and sessions
- **Scalability**: Minimal database impact with configurable cleanup

---

## Database Schema Changes Required

### 1. RefreshToken Table

```python
# New model to add to app/src/models/

from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Field, SQLModel

class RefreshToken(SQLModel, table=True):
    """Stores refresh tokens for persistent login"""
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    token_hash: str = Field(unique=True, index=True)  # Hash of token, not the token itself
    device_id: str = Field(index=True)                # Browser/device identifier
    device_name: Optional[str] = None                 # "Chrome on macOS", "Safari on iPhone"
    ip_address: Optional[str] = None                  # IP address of login
    user_agent: Optional[str] = None                  # Browser user agent
    is_remember_me: bool = Field(default=False)       # Extended expiry if true
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime                              # When this refresh token expires
    last_used_at: Optional[datetime] = None          # Track token usage
    revoked_at: Optional[datetime] = None            # Soft delete for revocation
    is_active: bool = Field(default=True, index=True) # Quick check for revocation
```

### 2. Alembic Migration

```python
# app/src/migrations/versions/2025_11_10_xxxx-add_refresh_token_table.py

def upgrade():
    op.create_table(
        'refreshtoken',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('device_name', sa.String(), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.String(), nullable=True),
        sa.Column('is_remember_me', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_refreshtoken_user_id'), 'refreshtoken', ['user_id'])
    op.create_index(op.f('ix_refreshtoken_token_hash'), 'refreshtoken', ['token_hash'])
    op.create_index(op.f('ix_refreshtoken_device_id'), 'refreshtoken', ['device_id'])
    op.create_index(op.f('ix_refreshtoken_is_active'), 'refreshtoken', ['is_active'])

def downgrade():
    op.drop_index(op.f('ix_refreshtoken_is_active'), table_name='refreshtoken')
    op.drop_index(op.f('ix_refreshtoken_device_id'), table_name='refreshtoken')
    op.drop_index(op.f('ix_refreshtoken_token_hash'), table_name='refreshtoken')
    op.drop_index(op.f('ix_refreshtoken_user_id'), table_name='refreshtoken')
    op.drop_table('refreshtoken')
```

### 3. LoginHistory Table (Optional but Recommended for Audit)

```python
class LoginHistory(SQLModel, table=True):
    """Audit trail for all login attempts"""
    id: int | None = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(foreign_key="user.id", index=True)  # None for failed attempts
    username: str = Field(index=True)  # Always record attempted username
    device_id: str
    device_name: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_successful: bool = Field(default=False, index=True)
    failure_reason: Optional[str] = None  # "invalid_password", "user_not_found", "account_locked"
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
```

---

## Enhanced Authentication Module

### 1. Update Settings

```python
# app/core/settings.py

class Settings(BaseSettings):
    # ... existing settings ...
    
    # Token Configuration
    access_token_expire_minutes: int = 15                    # SHORT-LIVED
    refresh_token_expire_days: int = 7                       # Standard persistent login
    refresh_token_remember_me_days: int = 30                 # "Remember me" duration
    algorithm: str = "HS256"
    secret_key: str
    refresh_token_secret_key: str                            # Separate key for refresh tokens
    
    # Security Configuration
    max_refresh_token_per_user: int = 5                      # Max active sessions per user
    enable_device_tracking: bool = True
    cleanup_expired_tokens_days: int = 1                     # Run cleanup daily
    
    model_config = SettingsConfigDict(env_file=".env")
```

### 2. Enhanced Authentication Functions

```python
# app/core/authentication.py - Add these functions

from secrets import token_urlsafe
from hashlib import sha256
from typing import Optional
from datetime import datetime, timedelta, timezone

def hash_token(token: str) -> str:
    """Hash token for secure storage (never store raw tokens)"""
    return sha256(token.encode()).hexdigest()

def generate_refresh_token() -> str:
    """Generate cryptographically secure refresh token"""
    return token_urlsafe(32)  # 256-bit token

def create_access_token(
    data: dict, 
    expires_delta: Optional[timedelta] = None
) -> dict:
    """Create short-lived JWT access token"""
    to_encode = data.copy()
    if "sub" not in to_encode:
        raise ValueError("Token payload must include 'sub' (username)")
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=int(settings.access_token_expire_minutes)
        )
    
    to_encode.update({
        "exp": expire,
        "token_type": "access"
    })
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.secret_key, 
        algorithm=settings.algorithm
    )
    
    return {
        "access_token": encoded_jwt,
        "token_type": "bearer",
        "expires_in": int(settings.access_token_expire_minutes * 60)  # seconds
    }

def create_refresh_token(
    user_id: int,
    device_id: str,
    remember_me: bool = False
) -> tuple[str, datetime]:
    """Create refresh token and return (token, expiry_datetime)"""
    refresh_token_str = generate_refresh_token()
    
    # Determine expiry based on remember_me flag
    if remember_me:
        expires_in = timedelta(days=int(settings.refresh_token_remember_me_days))
    else:
        expires_in = timedelta(days=int(settings.refresh_token_expire_days))
    
    expiry_datetime = datetime.now(timezone.utc) + expires_in
    
    return refresh_token_str, expiry_datetime

async def store_refresh_token(
    db: Session,
    user_id: int,
    refresh_token: str,
    device_id: str,
    device_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    remember_me: bool = False,
    expiry_datetime: Optional[datetime] = None
) -> "RefreshToken":
    """Store refresh token in database"""
    from app.src.models.refresh_token import RefreshToken
    
    if expiry_datetime is None:
        if remember_me:
            expiry_datetime = datetime.now(timezone.utc) + timedelta(
                days=int(settings.refresh_token_remember_me_days)
            )
        else:
            expiry_datetime = datetime.now(timezone.utc) + timedelta(
                days=int(settings.refresh_token_expire_days)
            )
    
    # Hash token before storing
    token_hash = hash_token(refresh_token)
    
    db_token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        device_id=device_id,
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        is_remember_me=remember_me,
        expires_at=expiry_datetime,
        created_at=datetime.now(timezone.utc),
        is_active=True
    )
    
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)
    return db_token

async def verify_refresh_token(
    db: Session,
    refresh_token: str,
    device_id: str
) -> Optional["RefreshToken"]:
    """Verify refresh token is valid and active"""
    from app.src.models.refresh_token import RefreshToken
    from sqlmodel import select
    
    token_hash = hash_token(refresh_token)
    
    result = await db.exec(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.device_id == device_id,
            RefreshToken.is_active == True,
            RefreshToken.revoked_at == None
        )
    )
    
    db_token = result.first()
    
    if not db_token:
        return None
    
    # Check if expired
    if db_token.expires_at <= datetime.now(timezone.utc):
        await revoke_refresh_token(db, db_token.id)
        return None
    
    return db_token

async def revoke_refresh_token(
    db: Session,
    token_id: int
):
    """Revoke a refresh token (soft delete)"""
    from app.src.models.refresh_token import RefreshToken
    from sqlmodel import select
    
    result = await db.exec(
        select(RefreshToken).where(RefreshToken.id == token_id)
    )
    token = result.first()
    
    if token:
        token.is_active = False
        token.revoked_at = datetime.now(timezone.utc)
        db.add(token)
        await db.commit()

async def revoke_all_user_tokens(
    db: Session,
    user_id: int
):
    """Revoke all refresh tokens for a user (logout all devices)"""
    from app.src.models.refresh_token import RefreshToken
    from sqlmodel import select
    
    result = await db.exec(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_active == True
        )
    )
    tokens = result.all()
    
    for token in tokens:
        token.is_active = False
        token.revoked_at = datetime.now(timezone.utc)
        db.add(token)
    
    await db.commit()

async def cleanup_expired_tokens(db: Session):
    """Background job to clean up expired tokens"""
    from app.src.models.refresh_token import RefreshToken
    from sqlmodel import delete
    
    # Delete tokens older than cleanup threshold
    cutoff_date = datetime.now(timezone.utc) - timedelta(
        days=int(settings.cleanup_expired_tokens_days)
    )
    
    await db.exec(
        delete(RefreshToken).where(
            RefreshToken.expires_at < cutoff_date,
            RefreshToken.is_active == False
        )
    )
    await db.commit()
```

---

## Enhanced Login Endpoints

### 1. Updated Login Endpoint with Remember Me

```python
# app/src/routes/auth.py - Replace existing login endpoint

from fastapi import Request
from app.core.authentication import (
    create_access_token,
    create_refresh_token,
    store_refresh_token,
    get_password_hash,
    verify_password,
    get_user,
)

@router.post("/login")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
    request: Request,
    remember_me: bool = False
):
    """
    Login endpoint with optional "remember me" functionality
    
    - remember_me: If true, refresh token expires in 30 days. Otherwise 7 days.
    """
    user = await get_user(session, form_data.username)
    
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    # Generate tokens
    access_token_data = create_access_token(data={"sub": user.username})
    refresh_token, expiry_dt = create_refresh_token(
        user_id=user.id,
        device_id=request.headers.get("X-Device-ID", "unknown"),
        remember_me=remember_me
    )
    
    # Store refresh token in database
    device_name = request.headers.get("X-Device-Name")
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    await store_refresh_token(
        db=session,
        user_id=user.id,
        refresh_token=refresh_token,
        device_id=request.headers.get("X-Device-ID", "unknown"),
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        remember_me=remember_me,
        expiry_datetime=expiry_dt
    )
    
    return {
        "access_token": access_token_data["access_token"],
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_data["expires_in"],
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "type": user.type,
            "name": user.name
        },
        "remember_me": remember_me
    }


@router.post("/refresh")
async def refresh_access_token(
    refresh_token: str,
    session: SessionDep,
    request: Request
):
    """
    Refresh an access token using a valid refresh token
    
    - Required: refresh_token in request body or header
    - Optional: X-Device-ID header to validate token is from same device
    """
    from app.core.authentication import verify_refresh_token
    
    device_id = request.headers.get("X-Device-ID", "unknown")
    
    # Verify refresh token
    db_token = await verify_refresh_token(session, refresh_token, device_id)
    
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    
    # Get user
    user = await session.get(User, db_token.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    # Create new access token
    access_token_data = create_access_token(data={"sub": user.username})
    
    # Update last_used_at
    db_token.last_used_at = datetime.now(timezone.utc)
    session.add(db_token)
    await session.commit()
    
    return {
        "access_token": access_token_data["access_token"],
        "token_type": "bearer",
        "expires_in": access_token_data["expires_in"]
    }


@router.post("/logout")
async def logout(
    current_user: Annotated[User, Depends(get_current_user)],
    session: SessionDep,
    request: Request
):
    """
    Logout user by revoking refresh token for current device
    
    Optional: add 'logout_all=true' query param to revoke all tokens
    """
    from app.core.authentication import revoke_refresh_token, revoke_all_user_tokens
    
    device_id = request.headers.get("X-Device-ID", "unknown")
    logout_all = request.query_params.get("logout_all", "false").lower() == "true"
    
    if logout_all:
        # Revoke all tokens for user
        await revoke_all_user_tokens(session, current_user.id)
        message = "Successfully logged out from all devices"
    else:
        # Revoke token for current device only
        from app.src.models.refresh_token import RefreshToken
        from sqlmodel import select
        
        result = await session.exec(
            select(RefreshToken).where(
                RefreshToken.user_id == current_user.id,
                RefreshToken.device_id == device_id,
                RefreshToken.is_active == True
            )
        )
        token = result.first()
        
        if token:
            await revoke_refresh_token(session, token.id)
        
        message = "Successfully logged out"
    
    return {"message": message}


@router.get("/sessions")
async def list_active_sessions(
    current_user: Annotated[User, Depends(get_current_user)],
    session: SessionDep
):
    """
    List all active sessions/devices for current user
    
    Useful for users to see where they're logged in and revoke suspicious sessions
    """
    from app.src.models.refresh_token import RefreshToken
    from sqlmodel import select
    
    result = await session.exec(
        select(RefreshToken).where(
            RefreshToken.user_id == current_user.id,
            RefreshToken.is_active == True
        )
    )
    tokens = result.all()
    
    sessions = [
        {
            "device_id": t.device_id,
            "device_name": t.device_name,
            "ip_address": t.ip_address,
            "last_used_at": t.last_used_at,
            "created_at": t.created_at,
            "is_remember_me": t.is_remember_me
        }
        for t in tokens
    ]
    
    return {"sessions": sessions}
```

---

## Configuration & Environment Variables

### Add to `.env`

```bash
# JWT Configuration
ALGORITHM=HS256
SECRET_KEY=your-super-secret-key-change-in-production
REFRESH_TOKEN_SECRET_KEY=another-secret-key-for-refresh-tokens

# Token Expiry
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
REFRESH_TOKEN_REMEMBER_ME_DAYS=30

# Security
MAX_REFRESH_TOKEN_PER_USER=5
ENABLE_DEVICE_TRACKING=true
CLEANUP_EXPIRED_TOKENS_DAYS=1
```

---

## Client-Side Integration

### JavaScript/TypeScript Client Implementation

```javascript
// utils/auth.js

const API_BASE = 'http://localhost:8000';

// Generate device ID (store in localStorage)
function getOrCreateDeviceId() {
    let deviceId = localStorage.getItem('deviceId');
    if (!deviceId) {
        deviceId = 'device_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('deviceId', deviceId);
    }
    return deviceId;
}

// Get device name from user agent
function getDeviceName() {
    const ua = navigator.userAgent;
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Safari')) return 'Safari';
    if (ua.includes('Firefox')) return 'Firefox';
    return 'Unknown Browser';
}

// Login with optional remember me
async function login(username, password, rememberMe = false) {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    formData.append('remember_me', rememberMe.toString());
    
    const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: {
            'X-Device-ID': getOrCreateDeviceId(),
            'X-Device-Name': getDeviceName()
        },
        body: formData,
        credentials: 'include'
    });
    
    if (!response.ok) {
        throw new Error('Login failed');
    }
    
    const data = await response.json();
    
    // Store tokens
    localStorage.setItem('accessToken', data.access_token);
    localStorage.setItem('refreshToken', data.refresh_token);
    localStorage.setItem('tokenExpiry', 
        new Date().getTime() + data.expires_in * 1000
    );
    
    return data;
}

// Refresh access token
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (!refreshToken) {
        throw new Error('No refresh token available');
    }
    
    const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Device-ID': getOrCreateDeviceId()
        },
        body: JSON.stringify({ refresh_token: refreshToken })
    });
    
    if (!response.ok) {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        throw new Error('Token refresh failed');
    }
    
    const data = await response.json();
    localStorage.setItem('accessToken', data.access_token);
    localStorage.setItem('tokenExpiry', 
        new Date().getTime() + data.expires_in * 1000
    );
    
    return data.access_token;
}

// Logout
async function logout(logoutAll = false) {
    const accessToken = localStorage.getItem('accessToken');
    
    const response = await fetch(
        `${API_BASE}/auth/logout?logout_all=${logoutAll}`,
        {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'X-Device-ID': getOrCreateDeviceId()
            }
        }
    );
    
    // Clear local storage regardless of response
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('tokenExpiry');
    
    return response.ok;
}

// Get valid access token (refresh if needed)
async function getValidAccessToken() {
    let accessToken = localStorage.getItem('accessToken');
    const expiry = localStorage.getItem('tokenExpiry');
    
    // Check if token is expired or about to expire (within 2 minutes)
    if (!expiry || new Date().getTime() + 120000 >= parseInt(expiry)) {
        try {
            accessToken = await refreshAccessToken();
        } catch (error) {
            // Refresh failed, user needs to login again
            logout();
            throw error;
        }
    }
    
    return accessToken;
}

// API request wrapper
async function apiRequest(endpoint, options = {}) {
    const accessToken = await getValidAccessToken();
    
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-Device-ID': getOrCreateDeviceId(),
        ...options.headers
    };
    
    return fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
    });
}
```

---

## Security Considerations

### 1. Token Storage
- **Access Token**: Store in memory or short-lived sessionStorage (not localStorage)
- **Refresh Token**: Can use httpOnly cookie (secure) or localStorage with HTTPS
- **Recommendation**: Use httpOnly, Secure, SameSite cookies for refresh tokens

### 2. Token Rotation
- Optionally issue new refresh token on every refresh
- Implement "refresh token rotation" for enhanced security

### 3. Rate Limiting
```python
# Add to auth routes
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@limiter.limit("5/minute")  # 5 attempts per minute
@router.post("/login")
async def login(...):
    ...

@limiter.limit("10/minute")  # 10 refresh attempts per minute
@router.post("/refresh")
async def refresh_access_token(...):
    ...
```

### 4. CSRF Protection
```python
# For state-changing operations
from fastapi_csrf_protect import CsrfProtect

@router.post("/logout")
async def logout(csrf_protect: CsrfProtect = Depends()):
    await csrf_protect.validate_csrf(request)
    ...
```

### 5. Logout and Token Revocation
- Remove refresh token from database immediately on logout
- Implement job to cleanup expired tokens periodically
- Consider implementing "logout all devices" feature

---

## Testing

### Test Examples for Refresh Token

```python
# app/src/tests/test_refresh_token.py

import pytest
from datetime import timedelta

@pytest.mark.asyncio
async def test_login_returns_refresh_token(client, test_user):
    """Test that login returns both access and refresh tokens"""
    response = client.post("/auth/login", data={
        "username": test_user.username,
        "password": "testpass123"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()

@pytest.mark.asyncio
async def test_refresh_token_creates_new_access_token(client, valid_refresh_token):
    """Test that refresh token creates new access token"""
    response = client.post("/auth/refresh", json={
        "refresh_token": valid_refresh_token
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_expired_refresh_token_rejected(client, expired_refresh_token):
    """Test that expired refresh tokens are rejected"""
    response = client.post("/auth/refresh", json={
        "refresh_token": expired_refresh_token
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_logout_invalidates_refresh_token(
    authenticated_client, 
    test_user,
    valid_refresh_token
):
    """Test that logout invalidates refresh token"""
    response = authenticated_client.post("/auth/logout")
    assert response.status_code == 200
    
    # Try to use the token
    refresh_response = authenticated_client.post("/auth/refresh", json={
        "refresh_token": valid_refresh_token
    })
    assert refresh_response.status_code == 401

@pytest.mark.asyncio
async def test_remember_me_extends_token_expiry(
    client, 
    test_user,
    session
):
    """Test that remember_me flag extends refresh token expiry"""
    response = client.post("/auth/login", data={
        "username": test_user.username,
        "password": "testpass123",
        "remember_me": "true"
    })
    
    assert response.status_code == 200
    data = response.json()
    
    # Check database that token has extended expiry
    token = await session.exec(
        select(RefreshToken).where(
            RefreshToken.user_id == test_user.id
        )
    )
    db_token = token.first()
    
    # Should be ~30 days from now, not 7
    assert db_token.is_remember_me == True
```

---

## Deployment Checklist

- [ ] Create database migration for RefreshToken table
- [ ] Update User model with new fields (if needed)
- [ ] Update authentication module with new functions
- [ ] Create new auth endpoints (refresh, logout, sessions)
- [ ] Update login endpoint to support remember_me
- [ ] Add environment variables to `.env`
- [ ] Implement refresh token cleanup job
- [ ] Add comprehensive tests
- [ ] Update API documentation/Swagger
- [ ] Set up httpOnly cookie support (if using cookies)
- [ ] Enable CORS for refresh endpoints
- [ ] Implement rate limiting on auth endpoints
- [ ] Add CSRF protection to logout endpoint
- [ ] Update frontend to use refresh token flow
- [ ] Test complete login/refresh/logout cycle
- [ ] Monitor database for token bloat (implement cleanup)

---

## Migration Path (Backward Compatibility)

If you want to maintain backward compatibility while adding new features:

1. **Phase 1**: Deploy refresh token infrastructure without requiring it
2. **Phase 2**: New clients use refresh tokens, old clients continue to work
3. **Phase 3**: Gradually deprecate old 4-hour token flow
4. **Phase 4**: Remove legacy token handling

```python
# During transition, support both flows:
@router.post("/login")
async def login(...):
    # Always return refresh token for new clients
    # Accept legacy clients without it
    ...
```

