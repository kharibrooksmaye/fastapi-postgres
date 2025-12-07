# FastAPI PostgreSQL Authentication Architecture Report

## Executive Summary

The current authentication implementation uses **JWT-based stateless authentication** with OAuth2 Bearer tokens. There is **no persistent login or "remember me" functionality** currently implemented. The system is suitable for stateless API usage but would require enhancements for production persistent login features.

---

## 1. Authentication Structure Overview

### Current Authentication Type: **JWT (JSON Web Tokens)**

The application implements a stateless JWT authentication system using:
- **Token Type**: Bearer tokens via OAuth2PasswordBearer
- **Signing Algorithm**: HS256 (HMAC with SHA-256)
- **Default Token Expiry**: 4 hours
- **Password Hashing**: bcrypt with passlib

### Architecture Diagram
```
User Login
    |
    v
POST /auth/login or /auth/token
    |
    v
Verify Credentials (username + password)
    |
    v
Generate JWT Access Token (expires in 4 hours)
    |
    v
Return Token to Client
    |
    v
Client sends token in Authorization header (Bearer token)
    |
    v
Dependency: get_current_user() validates token & retrieves user
```

---

## 2. Authentication-Related Files & Modules

### Core Authentication Files

| File | Purpose | Lines |
|------|---------|-------|
| `/app/core/authentication.py` | Core JWT logic, password handling, token creation/verification | 79 |
| `/app/core/authorization.py` | Role-based access control (RBAC) | 41 |
| `/app/src/routes/auth.py` | Authentication endpoints (login, register, token) | 106 |

### Database Models

| File | Model | Purpose |
|------|-------|---------|
| `/app/src/models/users.py` | `User` (SQLModel) | User table with 14 fields including is_active status |

### Schemas

| File | Schema | Purpose |
|------|--------|---------|
| `/app/src/schema/users.py` | `User`, `UserTypeEnum`, `ActivateUserRequest` | Data validation and user type enumeration |

### Database Configuration

| File | Purpose |
|------|---------|
| `/app/core/database.py` | Session management, PostgreSQL async connection |
| `/app/core/settings.py` | Environment configuration (secret_key, algorithm, tokens) |

### Test Files

| File | Coverage |
|------|----------|
| `/app/src/tests/test_core_authentication.py` | 20+ unit tests for password hashing, token creation/verification |
| `/app/src/tests/test_core_authorization.py` | Role-based access tests |
| `/app/src/tests/test_auth.py` | Integration tests for login, register, activation |

---

## 3. Token & Session Management Approach

### Token Creation Flow

**File**: `/app/core/authentication.py` (lines 32-45)

```python
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if "sub" not in to_encode:
        raise ValueError("Token payload must include 'sub' (username)")
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=4)  # DEFAULT: 4 HOURS
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm
    )
    expire_string = expire.strftime("%Y-%m-%d %H:%M:%S")
    return {"access_token": encoded_jwt, "expires": expire_string}
```

### Key Characteristics

1. **Stateless**: No server-side session storage required
2. **Self-contained**: All user info encoded in JWT payload
3. **Configurable Expiry**: Default 4 hours, customizable via `expires_delta` parameter
4. **Claims Structure**: Minimal payload - typically just `{"sub": username, "exp": timestamp}`
5. **No Refresh Tokens**: Currently no mechanism to refresh tokens without re-login

### Token Verification

**File**: `/app/core/authentication.py` (lines 48-58)

```python
def verify_token(token: str):
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None
```

**Limitations**:
- No token blacklisting (revoked tokens still valid until expiry)
- No token version checking
- No session tracking

### Current User Retrieval

**File**: `/app/core/authentication.py` (lines 61-78)

```python
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], db: SessionDep
) -> User:
    username = verify_token(token)
    if username is None:
        raise HTTPException(status_code=401, ...)
    user = await get_user(db, username=username)
    if user is None:
        raise HTTPException(status_code=401, ...)
    return user
```

**Flow**:
1. Extract token from Authorization header
2. Verify JWT signature and expiry
3. Extract username from `sub` claim
4. Query database to get full user object
5. Return user or raise 401 exception

---

## 4. Database Models for Authentication

### User Model

**File**: `/app/src/models/users.py`

```python
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    type: str = Field(default="patron", index=True)              # Role: patron, librarian, admin
    name: str = Field(index=True)
    email: Optional[str] = Field(index=True, unique=True)
    member_id: Optional[str] = Field(index=True, unique=True)
    phone_number: Optional[str] = None
    address: Optional[str] = None
    is_active: bool = Field(default=False)                       # Account activation status
    username: str = Field(index=True)
    password: str                                                 # bcrypt hashed
```

### Schema Validation

**File**: `/app/src/schema/users.py`

```python
class UserTypeEnum(str, Enum):
    patron = "patron"
    librarian = "librarian"
    admin = "admin"

class User(BaseModel):
    id: Union[int, None] = None
    type: UserTypeEnum = UserTypeEnum.patron
    name: str
    email: Union[str, None] = None
    member_id: Union[int, None] = None
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    is_active: Union[bool, None] = None
    username: str
    password: str

class ActivateUserRequest(BaseModel):
    email: Union[str, None] = None
    phone_number: Union[str, None] = None
    username: Union[str, None] = None
```

### Current Limitations

- **No device/session tracking**: Can't tie tokens to specific devices/browsers
- **No login history**: No audit trail of when/where users logged in
- **No persistent sessions table**: No server-side session storage
- **No refresh tokens**: Single token that expires; users must re-login
- **No "remember me" field**: No way to encode "remember this device" intention

---

## 5. Existing Persistent Login or "Remember Me" Functionality

### Current Status: **NONE**

There is no existing persistent login or "remember me" functionality in the codebase.

**Evidence**:
- No "remember_me" field in User model
- No refresh token implementation
- No session/device tracking table
- No cookie-based session handling
- No token blacklist/revocation system
- Grep search for "remember", "persistent", "session", "refresh_token" returns no relevant results

### Related Configuration

**File**: `/app/core/settings.py` - Only basic auth settings exist:

```python
class Settings(BaseSettings):
    secret_key: str                              # JWT signing key
    access_token_expire_minutes: str = "30"      # Intended for access token duration (currently overridden to 4 hours)
    algorithm: str = "HS256"                     # JWT algorithm
    # ... other settings (db, stripe, etc.)
```

**Note**: The setting `access_token_expire_minutes` defaults to "30" but is not used in the actual token creation (hardcoded to 4 hours in authentication.py:39).

---

## 6. Role-Based Access Control (RBAC)

### Implementation

**File**: `/app/core/authorization.py`

```python
def require_roles(allowed_roles: Union[str, List[str]]):
    """Check if user has one of the allowed roles"""
    
def require_minimum_role(minimum_role: str):
    """Check if user has minimum role level"""
    # Hierarchy: patron (1) < librarian (2) < admin (3)
```

### Usage Example

**File**: `/app/src/routes/users.py` (line 25)

```python
@router.get("/")
async def get_users(
    token: Annotated[str, Depends(oauth2_scheme)],
    admin: Annotated[User, Depends(require_roles(AdminRoleList))],
    ...
):
    # Only accessible to librarian or admin roles
```

---

## 7. Authentication Endpoints

### Endpoint Summary

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---|
| `/auth/login` | POST | Login with username/password, returns token + user | No |
| `/auth/token` | POST | OAuth2-compliant token endpoint | No |
| `/auth/register` | POST | Register new user | No |
| `/auth/activate/lookup` | POST | Activate pre-created user account | No |
| `/users/me/` | GET | Get current user info | Yes (Bearer token) |
| `/users/` | GET | List all users (admin only) | Yes |
| `/users/{user_id}` | GET | Get specific user (admin only) | Yes |

### Login Endpoint Details

**File**: `/app/src/routes/auth.py` (lines 18-30)

```python
@router.post("/login")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    session: SessionDep
):
    user = await get_user(session, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, ...)
    result = create_access_token(data={"sub": user.username})
    access_token, expires = result.values()
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "user": user, 
        "expires": expires
    }
```

---

## 8. Environment Configuration

**File**: `/app/core/settings.py`

```python
class Settings(BaseSettings):
    # Authentication
    secret_key: str                              # Required: JWT signing key
    access_token_expire_minutes: str = "30"      # Token expiry (unused - hardcoded to 4hrs)
    algorithm: str = "HS256"                     # JWT algorithm
    
    # Database
    db_endpoint: str
    db_user: str
    db_pw: str
    db_port: str
    db_name: str
    db_url: str
    test_db_url: str
    
    # ... other external services (Supabase, Stripe, etc.)
```

---

## 9. Dependencies & Available Libraries

**File**: `/pyproject.toml`

### Authentication-Related Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `python-jose` | ^3.3.0 | JWT encoding/decoding |
| `passlib` | ^1.7.4 | Password hashing abstraction |
| `bcrypt` | ^4.3.0 | bcrypt hashing algorithm |
| `fastapi` | ^0.116.1 | Web framework with OAuth2 support |
| `python-multipart` | ^0.0.20 | Form data parsing for OAuth2 |
| `sqlmodel` | ^0.0.24 | ORM with async support |

### Available for Enhancement

- Pydantic v2 (for validation)
- SQLAlchemy 2.0 (advanced session management)
- APScheduler (could implement token cleanup jobs)

---

## 10. Test Coverage

### Authentication Tests

**File**: `/app/src/tests/test_core_authentication.py` - 20+ tests covering:

- Password hashing consistency
- Password verification
- User lookup from database
- Access token creation (default & custom expiry)
- Token verification (valid, invalid, expired, malformed)
- Current user retrieval with valid/invalid/expired tokens
- Token payload structure

### Integration Tests

**File**: `/app/src/tests/test_auth.py` - Integration tests for:

- Login/token endpoints with valid credentials
- Login with invalid credentials
- User registration (success & duplicates)
- User activation lookup
- Authentication state mocking

### Authorization Tests

**File**: `/app/src/tests/test_core_authorization.py` - RBAC tests

---

## 11. Current Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Application                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │          Authentication Routes (/auth)              │  │
│  │  ├── POST /login          → create_access_token()  │  │
│  │  ├── POST /token          → create_access_token()  │  │
│  │  ├── POST /register       → hash password + save   │  │
│  │  └── POST /activate/lookup → activate user         │  │
│  └─────────────────────────────────────────────────────┘  │
│                         │                                   │
│                         v                                   │
│  ┌─────────────────────────────────────────────────────┐  │
│  │      Core Authentication Module                      │  │
│  │  ├── create_access_token()  → JWT (4hr expiry)     │  │
│  │  ├── verify_token()         → extract username     │  │
│  │  ├── get_current_user()     → user from DB + JWT   │  │
│  │  ├── get_password_hash()    → bcrypt hashing       │  │
│  │  └── verify_password()      → bcrypt verification  │  │
│  └─────────────────────────────────────────────────────┘  │
│                         │                                   │
│                         v                                   │
│  ┌─────────────────────────────────────────────────────┐  │
│  │     Authorization Module (Role-Based)               │  │
│  │  ├── require_roles()        → single role check     │  │
│  │  └── require_minimum_role() → hierarchy check       │  │
│  └─────────────────────────────────────────────────────┘  │
│                         │                                   │
└─────────────────────────────────────────────────────────────┘
                          │
                          v
┌─────────────────────────────────────────────────────────────┐
│                   PostgreSQL Database                       │
│  ┌────────────────────────────────────────────────────┐   │
│  │  Users Table                                       │   │
│  │  ├── id (PK)                                      │   │
│  │  ├── username (indexed)                           │   │
│  │  ├── password (bcrypt hashed)                     │   │
│  │  ├── email (unique)                               │   │
│  │  ├── type (patron/librarian/admin)                │   │
│  │  ├── is_active (boolean)                          │   │
│  │  └── other fields (name, phone, address, etc.)    │   │
│  └────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

STATELESS JWT FLOW:
┌──────────┐         ┌─────────────────┐         ┌──────────────┐
│  Client  │────────▶│  FastAPI Server │────────▶│  PostgreSQL  │
│          │ POST    │                 │ Query   │              │
│  Login   │ username│ Validate + JWT  │ username│   Verify     │
│  Password│ password│ Generation      │         │   credentials│
│          │◀────────│                 │◀────────│              │
│          │ JWT +   │                 │ user    │              │
│          │ expires │                 │ record  │              │
└──────────┘         └─────────────────┘         └──────────────┘

SUBSEQUENT REQUESTS:
┌──────────┐         ┌─────────────────┐
│  Client  │────────▶│  FastAPI Server │
│          │ Bearer  │ Verify JWT      │
│  With    │ JWT     │ Extract username│
│  Token   │         │ Query DB for    │
│          │◀────────│ full user obj   │
│          │ Response│                 │
└──────────┘         └─────────────────┘
```

---

## 12. Production Readiness Assessment

### Current Strengths
- bcrypt password hashing (industry standard)
- JWT-based stateless authentication (scalable)
- Role-based access control (RBAC) implemented
- Comprehensive test coverage
- Async database operations
- Proper HTTP status codes and error handling

### Critical Gaps for Production Persistent Login

| Gap | Impact | Priority |
|-----|--------|----------|
| No refresh tokens | Users must re-login every 4 hours | HIGH |
| No token blacklist | Revoked tokens still valid | HIGH |
| No device tracking | Can't differentiate login devices | MEDIUM |
| No login history | No audit trail | MEDIUM |
| No "remember me" option | Can't extend session for trusted devices | MEDIUM |
| No session invalidation | Can't force logout across devices | MEDIUM |
| No CSRF protection | Vulnerable to cross-site attacks | HIGH |
| No rate limiting | Brute force attacks possible | MEDIUM |

### Recommended Enhancements

1. **Implement Refresh Tokens** - Allow token renewal without re-login
2. **Add Token Blacklist** - Revoke tokens immediately on logout
3. **Implement Device/Session Tracking** - Store user sessions with device info
4. **Add "Remember Me" Checkbox** - Extend expiry for trusted devices
5. **CSRF Protection** - Add CSRF tokens for state-changing operations
6. **Rate Limiting** - Limit login attempts and token refreshes
7. **Login History Audit Log** - Track all authentication events

---

## Key Files Reference

| File | Lines | Purpose |
|------|-------|---------|
| `/app/core/authentication.py` | 79 | Core JWT and password management |
| `/app/core/authorization.py` | 41 | Role-based access control |
| `/app/src/routes/auth.py` | 106 | Authentication endpoints |
| `/app/src/models/users.py` | 14 | User database model |
| `/app/src/schema/users.py` | 30 | User data validation schemas |
| `/app/core/settings.py` | 31 | Configuration management |
| `/app/core/database.py` | 58 | Database session management |
| `/app/src/tests/test_core_authentication.py` | 346 | Authentication unit tests |
| `/app/src/tests/test_auth.py` | 111 | Integration tests |

---

## Summary Table

| Aspect | Current Implementation | Status |
|--------|----------------------|--------|
| **Auth Type** | JWT (stateless) | Production-ready |
| **Token Expiry** | 4 hours (hardcoded) | Functional |
| **Password Hashing** | bcrypt | Secure |
| **Session Storage** | None (stateless) | Limited |
| **Refresh Tokens** | Not implemented | Missing |
| **Device Tracking** | Not implemented | Missing |
| **Persistent Login** | Not implemented | Missing |
| **Token Blacklist** | Not implemented | Missing |
| **RBAC** | Implemented (3 roles) | Functional |
| **Test Coverage** | Comprehensive | Good |

