# Authentication Architecture - Visual Reference Guide

## Current Architecture Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT BROWSER                              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                    1. POST /auth/login
                    (username, password)
                                │
                                v
        ┌───────────────────────────────────────────┐
        │      FastAPI Server (/app/main.py)        │
        ├───────────────────────────────────────────┤
        │  ┌────────────────────────────────────┐   │
        │  │   Auth Routes (/auth)              │   │
        │  │                                    │   │
        │  │  POST /login                       │   │
        │  │  POST /token                       │   │
        │  │  POST /register                    │   │
        │  │  POST /activate/lookup             │   │
        │  └────────────────────────────────────┘   │
        │                 │                          │
        │                 v                          │
        │  ┌────────────────────────────────────┐   │
        │  │  Authentication Module             │   │
        │  │  (/app/core/authentication.py)     │   │
        │  │                                    │   │
        │  │  create_access_token()             │   │
        │  │  verify_token()                    │   │
        │  │  get_current_user()                │   │
        │  │  get_password_hash()               │   │
        │  │  verify_password()                 │   │
        │  └────────────────────────────────────┘   │
        │                 │                          │
        │                 v                          │
        │  ┌────────────────────────────────────┐   │
        │  │  Authorization Module              │   │
        │  │  (/app/core/authorization.py)      │   │
        │  │                                    │   │
        │  │  require_roles()                   │   │
        │  │  require_minimum_role()            │   │
        │  └────────────────────────────────────┘   │
        │                 │                          │
        └─────────────────┼──────────────────────────┘
                          │
            2. Query users table
            3. Hash & verify password
            4. Generate JWT (4 hr expiry)
                          │
                          v
        ┌───────────────────────────────────────────┐
        │     PostgreSQL Database                   │
        ├───────────────────────────────────────────┤
        │                                           │
        │  ┌─────────────────────────────────┐     │
        │  │ Users Table (users)             │     │
        │  ├─────────────────────────────────┤     │
        │  │ id (PK)                         │     │
        │  │ username (indexed)              │     │
        │  │ password (bcrypt hashed)        │     │
        │  │ email (unique)                  │     │
        │  │ type (patron/librarian/admin)   │     │
        │  │ is_active (bool)                │     │
        │  │ ... other fields                │     │
        │  └─────────────────────────────────┘     │
        │                                           │
        │  NO SESSION/DEVICE TRACKING               │
        │  NO REFRESH TOKEN TABLE                   │
        │  NO LOGIN HISTORY TABLE                   │
        │                                           │
        └───────────────────────────────────────────┘
                          │
                          v
        ┌───────────────────────────────────────────┐
        │  Response to Client                       │
        │  {                                        │
        │    "access_token": "eyJhbGc...",          │
        │    "token_type": "bearer",                │
        │    "expires": "2024-11-10 14:00:00",      │
        │    "user": {...}                          │
        │  }                                        │
        └───────────────────────────────────────────┘
                          │
                          v
        ┌───────────────────────────────────────────┐
        │  Client Stores Token (localStorage)       │
        │  localStorage.setItem('token', ...)       │
        └───────────────────────────────────────────┘
                          │
                          v
        ┌───────────────────────────────────────────┐
        │  Subsequent Requests                      │
        │  Authorization: Bearer <token>            │
        │  GET /users/me/                           │
        │  GET /catalog/items                       │
        │  POST /circulation/checkout               │
        └───────────────────────────────────────────┘
                          │
                          v
        ┌───────────────────────────────────────────┐
        │  Server Verifies Token                    │
        │  1. Extract token from header             │
        │  2. Verify JWT signature                  │
        │  3. Check expiry                          │
        │  4. Extract username from 'sub' claim     │
        │  5. Query DB for full user object         │
        │  6. Check role authorization              │
        └───────────────────────────────────────────┘
```

## Problem: Token Expires After 4 Hours

```
LOGIN                    AFTER 4 HOURS              USER TRIES ACTION
  │                            │                           │
  v                            v                           v
┌────────────┐           ┌────────────┐           ┌────────────────┐
│ User logs  │           │ TOKEN      │           │ Token invalid  │
│ in, gets   │──────────▶│ EXPIRES    │──────────▶│ User must      │
│ 4-hr token │           │            │           │ re-login       │
└────────────┘           └────────────┘           └────────────────┘

CURRENT PROBLEM: No way to extend session without re-login
```

## Proposed Solution: Hybrid JWT + Refresh Token

```
LOGIN                                          BEFORE EXPIRY
  │                                                  │
  v                                                  v
┌────────────────────────────────────────┐   ┌─────────────────────────┐
│ User logs in with "Remember Me"        │   │ Check token expiry      │
│ ✓ Remember Me checkbox checked         │   │ (Before 4 hours)        │
└─────────────────────────────┬──────────┘   └──────────┬──────────────┘
                              │                         │
                              v                         v
         ┌────────────────────────────────┐   ┌──────────────────────┐
         │ Server generates:              │   │ POST /auth/refresh   │
         ├────────────────────────────────┤   ├──────────────────────┤
         │ 1. Short-lived ACCESS token    │   │ Send: refresh_token  │
         │    (15 min expiry)             │   │       device_id      │
         │                                │   │                      │
         │ 2. Long-lived REFRESH token    │   │ Get: new access_token│
         │    (30 days with remember_me)  │   │      expires_in      │
         │    (7 days without)            │   └──────────────────────┘
         │                                │
         │ 3. Stores refresh token in DB  │
         │    RefreshToken table          │
         │    - token_hash                │   ✓ Automatic
         │    - device_id                 │   ✓ No re-login
         │    - device_name               │   ✓ Extended session
         │    - ip_address                │
         │    - expires_at                │
         │    - is_remember_me: true      │
         └────────────────────────────────┘

WORKFLOW TIMELINE:
0 min:   User logs in with "Remember Me"
         - GET access_token (15 min expiry)
         - GET refresh_token (30 days expiry)
         - Token stored in DB

15 min:  Access token expires
         - Auto-refresh: POST /auth/refresh
         - GET new access_token (15 min expiry)
         - Refresh token still valid

24 hrs:  Still using app, auto-refreshing every 15 min

7 days:  If "Remember Me" NOT checked, refresh_token expires
         - User must re-login

30 days: If "Remember Me" checked, refresh_token expires
         - User must re-login

ANY TIME: User clicks logout
         - DELETE refresh_token from DB
         - Token immediately invalid
         - Must re-login to continue
```

## File Structure Overview

```
/Users/kharibrooksmaye/Documents/GitHub/fastapi-postgres/
├── app/
│   ├── core/
│   │   ├── authentication.py          ← JWT, password handling, token creation
│   │   ├── authorization.py           ← Role-based access control
│   │   ├── database.py                ← PostgreSQL async connection
│   │   ├── settings.py                ← Configuration (secret_key, algorithm, etc.)
│   │   └── logging.py
│   │
│   ├── src/
│   │   ├── models/
│   │   │   └── users.py               ← User table definition
│   │   │   # NEED TO ADD: refresh_token.py
│   │   │   # NEED TO ADD: login_history.py
│   │   │
│   │   ├── schema/
│   │   │   └── users.py               ← User validation schemas
│   │   │
│   │   ├── routes/
│   │   │   ├── auth.py                ← Login, register, token endpoints
│   │   │   ├── users.py               ← User management endpoints
│   │   │   ├── circulation.py
│   │   │   ├── items.py
│   │   │   └── fines.py
│   │   │
│   │   ├── migrations/
│   │   │   └── versions/
│   │   │       # NEED TO ADD: xxxx_add_refresh_token_table.py
│   │   │       # NEED TO ADD: xxxx_add_login_history_table.py
│   │   │
│   │   └── tests/
│   │       ├── test_core_authentication.py    ← 20+ unit tests
│   │       ├── test_core_authorization.py     ← RBAC tests
│   │       ├── test_auth.py                   ← Integration tests
│   │       # NEED TO ADD: test_refresh_token.py
│   │       # NEED TO ADD: test_persistent_login.py
│   │       └── conftest.py
│   │
│   └── main.py                         ← FastAPI app entry point
│
├── pyproject.toml                      ← Dependencies
├── AUTH_ARCHITECTURE_REPORT.md         ← Current state analysis
├── PERSISTENT_LOGIN_IMPLEMENTATION.md  ← Implementation guide
├── AUTHENTICATION_SUMMARY.md           ← Quick reference
└── AUTHENTICATION_VISUAL_GUIDE.md      ← This file
```

## Token Lifecycle Comparison

### Current (4-Hour Stateless JWT)

```
Time:  0h      1h      2h      3h      4h      5h
       │       │       │       │       │       │
Token: ├───────┼───────┼───────┼───────┤       │
       VALID   VALID   VALID   VALID   EXPIRES INVALID
                                        │
                                        USER MUST RE-LOGIN
```

### Proposed (Hybrid with Remember Me)

```
Time:  0h   15m  30m  45m  1h  2h   3h   4h          7d    14d   30d
ACCESS │ ├──┤ ├──┤ ├──┤ ├──┤ ├──┤ ├──┤ ├──┤...REFRESHING...├───┤
TOKEN: └────────────────────────────────────────────────────────┘
       (Expires every 15 min, AUTO-REFRESHES)

REFRESH┌──────────────────────────────────────────────────────────┐
TOKEN: │ WITH "REMEMBER ME" - 30 DAYS EXPIRY                     │
       └──────────────────────────────────────────────────────────┘
       ├─────────── WITHOUT "REMEMBER ME" - 7 DAYS ────────────┤
       └──────────────────────────────────────────────────────┘

AFTER LOGOUT:
       IMMEDIATELY REVOKED (deleted from database)
       Cannot be refreshed anymore
       User MUST re-login
```

## Database Schema: Before vs After

### BEFORE (Current)

```
┌─────────────────────────────┐
│ Users Table                 │
├─────────────────────────────┤
│ id (PK)                     │
│ username                    │
│ password (bcrypt hashed)    │
│ email                       │
│ member_id                   │
│ type (role)                 │
│ is_active                   │
│ phone_number                │
│ address                     │
│ name                        │
└─────────────────────────────┘

PROBLEM: No session/device tracking
         No token management
         No logout capability
         No device differentiation
```

### AFTER (Proposed)

```
┌─────────────────────────────┐      ┌──────────────────────────────┐
│ Users Table                 │      │ RefreshToken Table (NEW)     │
├─────────────────────────────┤      ├──────────────────────────────┤
│ id (PK)                 ┐   │      │ id (PK)                      │
│ username                │ ├─┼─────▶│ user_id (FK)                 │
│ password                │ │ │      │ token_hash (indexed)         │
│ email                   │ │ │      │ device_id (indexed)          │
│ member_id               │ │ │      │ device_name                  │
│ type (role)             │ │ │      │ ip_address                   │
│ is_active               │ │ │      │ user_agent                   │
│ phone_number            │ │ │      │ is_remember_me (bool)        │
│ address                 │ │ │      │ created_at                   │
│ name                    │ │ │      │ expires_at (indexed)         │
└─────────────────────────────┘      │ last_used_at                 │
                                      │ revoked_at                   │
                                      │ is_active (bool, indexed)    │
                                      └──────────────────────────────┘

                  ┌──────────────────────────────┐
                  │ LoginHistory Table (NEW)     │
                  ├──────────────────────────────┤
                  │ id (PK)                      │
                  │ user_id (FK, nullable)       │
                  │ username                     │
                  │ device_id                    │
                  │ device_name                  │
                  │ ip_address                   │
                  │ user_agent                   │
                  │ is_successful (bool)         │
                  │ failure_reason               │
                  │ timestamp (indexed)          │
                  └──────────────────────────────┘

SOLUTION: Can track sessions per device
          Can revoke tokens immediately
          Can distinguish between devices
          Can audit login attempts
          Can detect suspicious activity
```

## API Endpoints: Current vs Proposed

### CURRENT

```
POST /auth/login
  Input:  username, password
  Output: access_token (4h), user data
  Behavior: Generate JWT, no refresh

POST /auth/token
  Input:  username, password
  Output: access_token (4h)
  Behavior: OAuth2 standard endpoint

POST /auth/register
  Input:  user data
  Output: user object
  Behavior: Create new user account

POST /auth/activate/lookup
  Input:  email, phone, username
  Output: activation message
  Behavior: Activate pre-created account

GET /users/me/
  Auth: Bearer token
  Output: current user data
  Behavior: Get logged-in user info

GET /users/
  Auth: Bearer token (admin only)
  Output: list of users
  Behavior: List all users

DELETE /users/{user_id}
  Auth: Bearer token (admin only)
  Output: success message
  Behavior: Delete user account
```

### PROPOSED ADDITIONS

```
POST /auth/refresh
  Input:  refresh_token, device_id
  Output: new access_token (15m), expires_in
  Behavior: Refresh access token using refresh token
  Error: 401 if token expired or revoked

POST /auth/logout
  Auth: Bearer token
  Input:  (optional) logout_all=true
  Output: success message
  Behavior: Revoke refresh token(s) for device
  Side effect: Delete refresh token from DB

GET /auth/sessions
  Auth: Bearer token
  Output: [
    {
      device_id,
      device_name,
      ip_address,
      last_used_at,
      created_at,
      is_remember_me
    }
  ]
  Behavior: List all user's active sessions

DELETE /auth/sessions/{device_id}
  Auth: Bearer token
  Output: success message
  Behavior: Log out specific device
  Side effect: Revoke that device's refresh token
```

## Security Considerations Map

```
┌──────────────────────────────────────────────────────────────┐
│  SECURITY MEASURE          │  CURRENT  │  PROPOSED           │
├──────────────────────────────────────────────────────────────┤
│ Password hashing (bcrypt)  │    ✓      │    ✓                │
│ JWT signature validation   │    ✓      │    ✓                │
│ Token expiry checking      │    ✓      │    ✓ (both tokens)  │
│ Role-based access control  │    ✓      │    ✓                │
│                            │           │                     │
│ Token refresh without DB   │    ✓      │    ✗ (uses DB)      │
│ Immediate logout support   │    ✗      │    ✓ (DB revoke)    │
│ Device tracking            │    ✗      │    ✓                │
│ Token rotation             │    ✗      │    ~ (optional)     │
│ Login history audit        │    ✗      │    ✓ (new table)    │
│ Rate limiting              │    ✗      │    ✓ (slowapi)      │
│ CSRF protection            │    ✗      │    ✓ (fastapi-csrf) │
│ HttpOnly cookie support    │    ✗      │    ✓ (optional)     │
│ Token blacklist            │    ✗      │    ✓ (soft delete)  │
│                            │           │                     │
│ OVERALL SECURITY           │  BASIC    │  ENTERPRISE-GRADE   │
└──────────────────────────────────────────────────────────────┘
```

## Implementation Priority Matrix

```
        HIGH IMPACT
             │
        ┌────┴────────────────────────┐
        │                              │
  HIGH  │ Refresh Tokens              │ Device Tracking
  EFFORT│ Token Blacklist             │ Login History
        │ Logout Endpoint             │
        │                              │
        │                              │ Rate Limiting
        │                              │ CSRF Protection
   LOW  │ "Remember Me" Flag          │
  EFFORT│                              │
        │                              │
        └────┬──────────────────────┬──┘
             LOW IMPACT   HIGH IMPACT

RECOMMENDATION: Start with top-left quadrant (high impact, high effort but worth it)
                Then add low-effort, high-impact items
                Optional: Add polish items (rate limiting, CSRF)
```

## Quick Implementation Checklist

```
PHASE 1: Core Refresh Token System (2-3 hours)
  □ Create RefreshToken model
  □ Create Alembic migration
  □ Add database functions (store, verify, revoke)
  □ Update settings with new configuration
  □ Implement /auth/refresh endpoint
  □ Add basic tests

PHASE 2: Login & Logout (1-2 hours)
  □ Update /auth/login to return refresh token
  □ Add "remember_me" parameter
  □ Implement /auth/logout endpoint
  □ Add comprehensive tests
  □ Update client-side code

PHASE 3: Session Management (1-2 hours)
  □ Create LoginHistory model (optional)
  □ Implement /auth/sessions endpoint
  □ Add device tracking
  □ Add device revocation endpoint
  □ Add tests

PHASE 4: Security Hardening (1-2 hours)
  □ Add rate limiting (slowapi)
  □ Add CSRF protection (fastapi-csrf)
  □ Implement token cleanup job
  □ Add login attempt logging
  □ Security testing

PHASE 5: Deployment (1 hour)
  □ Configure environment variables
  □ Run migrations on production
  □ Update frontend
  □ Monitor token table growth
  □ Validate complete flow

TOTAL: 6-10 hours for full implementation
```

