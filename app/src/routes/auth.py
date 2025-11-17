from typing import Annotated
import secrets
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import or_, select
from app.core.authentication import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    get_password_hash,
    get_user,
    get_user_sessions,
    revoke_all_user_tokens,
    revoke_refresh_token,
    store_csrf_token,
    verify_and_get_refresh_token,
    verify_csrf_token,
    verify_password,
)
from app.core.database import SessionDep
from app.core.settings import settings
from app.src.models.users import User
from app.src.schema.users import ActivateUserRequest

router = APIRouter()


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

    # Generate CSRF token for additional security
    csrf_token = secrets.token_urlsafe(32)
    await store_csrf_token(session, user.id, csrf_token)

    # Set refresh token as httpOnly cookie for XSS protection
    max_age = (
        settings.refresh_token_remember_me_days * 86400
        if remember_me
        else settings.refresh_token_expire_days * 86400
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,  # Prevents JavaScript access (XSS protection)
        secure=settings.environment != "development",  # False for local dev, True for production
        samesite="strict",  # CSRF protection
        max_age=max_age,
        path="/auth",  # Only send cookie to /auth endpoints
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,  # Backward compatibility (temporary)
        "csrf_token": csrf_token,  # Client stores in localStorage
        "token_type": "bearer",
        "user": user,
        "expires": access_expires,
        "refresh_expires": refresh_expires.strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.post("/token")
async def get_token(
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

    # Generate CSRF token for additional security
    csrf_token = secrets.token_urlsafe(32)
    await store_csrf_token(session, user.id, csrf_token)

    # Set refresh token as httpOnly cookie for XSS protection
    max_age = (
        settings.refresh_token_remember_me_days * 86400
        if remember_me
        else settings.refresh_token_expire_days * 86400
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,  # Prevents JavaScript access (XSS protection)
        secure=settings.environment != "development",  # False for local dev, True for production
        samesite="strict",  # CSRF protection
        max_age=max_age,
        path="/auth",  # Only send cookie to /auth endpoints
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,  # Backward compatibility (temporary)
        "csrf_token": csrf_token,  # Client stores in localStorage
        "token_type": "bearer",
        "expires": access_expires,
        "refresh_expires": refresh_expires.strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.post("/register", response_model=User)
async def register_user(user: User, session: SessionDep):
    if not user or not user.username or not user.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required",
        )
    existing_user = await get_user(session, user.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    try:
        user.password = get_password_hash(user.password)
        session.add(user)
        await session.commit()
        return user
    except Exception as e:
        print(f"Error registering user: {e}")
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user",
        )


@router.post("/activate/lookup")
async def activate_user_lookup(
    data: Annotated[ActivateUserRequest, Form()], session: SessionDep
):
    email = data.email
    username = data.username
    phone_number = data.phone_number
    result = await session.exec(
        select(User).where(
            or_(
                User.email == email,
                User.username == username,
                User.phone_number == phone_number,
            )
        )
    )
    user = result.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found with provided email and phone number",
        )
    if user.username or user.password:
        return {
            "status_code": status.HTTP_206_PARTIAL_CONTENT,
            "detail": "User has already been activated, please log in",
        }
    user.is_active = True
    session.add(user)
    await session.commit()
    return {"message": f"User '{user.username}' activated successfully."}


# Refresh Token Endpoints


@router.post("/refresh")
async def refresh_access_token(
    request: Request,
    session: SessionDep,
    refresh_token: str | None = Body(None, embed=True),
):
    """
    Exchange a valid refresh token for a new access token.
    The refresh token can be provided either:
    1. Via httpOnly cookie (preferred for security)
    2. In the request body (backward compatibility)

    When using httpOnly cookies, a CSRF token must be provided via X-CSRF-Token header.
    """
    # Try to get refresh token from cookie first, fall back to body
    token_value = request.cookies.get("refresh_token", refresh_token)

    if not token_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If token came from cookie, verify CSRF token
    csrf_token = request.headers.get("X-CSRF-Token")
    using_cookie = "refresh_token" in request.cookies

    token_record = await verify_and_get_refresh_token(session, token_value)

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get the user associated with this token
    user = await session.get(User, token_record.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify CSRF token if using cookie-based authentication
    if using_cookie:
        if not csrf_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token required when using cookie-based authentication",
            )

        csrf_valid = await verify_csrf_token(session, user.id, csrf_token)
        if not csrf_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid CSRF token",
            )

    # Create new access token
    result = create_access_token(data={"sub": user.username})
    access_token, expires = result.values()

    response_data = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires": expires,
    }

    # Include CSRF token in response if using cookie-based auth
    if using_cookie and csrf_token:
        response_data["csrf_token"] = csrf_token

    return response_data


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_user)],
    refresh_token: str | None = Body(None, embed=True),
):
    """
    Logout the user by revoking their refresh token(s).

    Token priority:
    1. Refresh token from httpOnly cookie (preferred)
    2. Refresh token from request body (backward compatibility)

    If a specific refresh_token is identified, only that token is revoked.
    If no token is provided, all tokens for the user are revoked.

    Always clears the httpOnly cookie on logout.
    """
    # Get refresh token from cookie or body
    token_value = request.cookies.get("refresh_token", refresh_token)

    # Clear the httpOnly cookie regardless of logout method
    response.delete_cookie(key="refresh_token", path="/auth")

    if token_value:
        # Revoke specific token
        token_record = await verify_and_get_refresh_token(session, token_value)
        if token_record and token_record.user_id == current_user.id:
            success = await revoke_refresh_token(session, token_record.id)
            if success:
                return {"message": "Logged out successfully"}
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )
    else:
        # Revoke all tokens for user (logout from all devices)
        count = await revoke_all_user_tokens(session, current_user.id)
        return {"message": f"Logged out from {count} device(s) successfully"}


@router.get("/sessions")
async def get_sessions(
    session: SessionDep, current_user: Annotated[User, Depends(get_current_user)]
):
    """
    Get all active sessions (refresh tokens) for the current user.
    Returns a list of devices with their last activity.
    """
    sessions = await get_user_sessions(session, current_user.id)

    return {
        "sessions": [
            {
                "id": s.id,
                "device_name": s.device_name,
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "last_used_at": (
                    s.last_used_at.strftime("%Y-%m-%d %H:%M:%S")
                    if s.last_used_at
                    else None
                ),
                "expires_at": s.expires_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for s in sessions
        ]
    }


@router.delete("/sessions/{token_id}")
async def revoke_session(
    token_id: int,
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Revoke a specific session (refresh token) by its ID.
    Users can only revoke their own tokens.
    """
    # Verify the token belongs to the current user
    sessions = await get_user_sessions(session, current_user.id)
    token_ids = [s.id for s in sessions]

    if token_id not in token_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or does not belong to you",
        )

    success = await revoke_refresh_token(session, token_id)
    if success:
        return {"message": "Session revoked successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
        )
