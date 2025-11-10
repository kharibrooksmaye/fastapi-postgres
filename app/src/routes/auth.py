from typing import Annotated
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, status
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
    verify_and_get_refresh_token,
    verify_password,
)
from app.core.database import SessionDep
from app.src.models.users import User
from app.src.schema.users import ActivateUserRequest

router = APIRouter()


@router.post("/login")
async def login(
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

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user,
        "expires": access_expires,
        "refresh_expires": refresh_expires.strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.post("/token")
async def get_token(
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

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
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
    session: SessionDep, refresh_token: str = Body(..., embed=True)
):
    """
    Exchange a valid refresh token for a new access token.
    The refresh token must be valid, not revoked, and not expired.
    """
    token_record = await verify_and_get_refresh_token(session, refresh_token)

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

    # Create new access token
    result = create_access_token(data={"sub": user.username})
    access_token, expires = result.values()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires": expires,
    }


@router.post("/logout")
async def logout(
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_user)],
    refresh_token: str = Body(None, embed=True),
):
    """
    Logout the user by revoking their refresh token(s).
    If refresh_token is provided, only that token is revoked.
    If not provided, all tokens for the user are revoked.
    """
    if refresh_token:
        # Revoke specific token
        token_record = await verify_and_get_refresh_token(session, refresh_token)
        if token_record and token_record.user_id == current_user.id:
            success = await revoke_refresh_token(session, token_record.id)
            if success:
                return {"message": "Logged out successfully"}
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )
    else:
        # Revoke all tokens for user
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
