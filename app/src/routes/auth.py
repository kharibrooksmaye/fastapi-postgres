from typing import Annotated
import secrets
from fastapi import (
    APIRouter,
    Body,
    Depends,
    Form,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlmodel import or_, select
from app.core.authentication import (
    activate_user_with_token,
    create_access_token,
    create_activation_token,
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
from app.core.email import send_activation_email
from app.core.settings import settings
from app.src.models.users import User
from app.src.schema.users import ActivateUserRequest

router = APIRouter()


async def handle_inactive_user_with_token_check(user: User, session: SessionDep) -> HTTPException:
    """
    Handle inactive user authentication by checking token expiry and resending if needed.
    Returns appropriate HTTPException with activation status and email resend info.
    """
    from datetime import datetime, timezone
    
    # Check if activation token is older than 48 hours or doesn't exist
    should_resend_email = False
    
    if not user.activation_token_hash or not user.activation_token_expires:
        # No activation token exists, need to create and send one
        should_resend_email = True
    else:
        # Check if token is expired (current time > expiry time)
        # Handle timezone-aware/naive datetime comparison safely
        current_time = datetime.now(timezone.utc)
        expires_time = user.activation_token_expires
        
        # Make sure both datetimes are timezone-aware for comparison
        if expires_time.tzinfo is None:
            expires_time = expires_time.replace(tzinfo=timezone.utc)
            
        if current_time > expires_time:
            should_resend_email = True
    
    # Resend activation email if token is expired
    if should_resend_email:
        try:
            # Create new activation token
            activation_token = await create_activation_token(session, user.id)
            
            # Send new activation email
            await send_activation_email(
                email=user.email,
                username=user.username,
                activation_token=activation_token
            )
            
            # Update response to indicate email was resent
            return HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not activated. A new activation email has been sent to your email address.",
                headers={
                    "X-Account-Status": "inactive",
                    "X-Action-Required": "activation", 
                    "X-User-Email": user.email,
                    "X-Email-Resent": "true"
                }
            )
        except Exception:
            # If email sending fails, still inform user but don't expose error
            return HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not activated. Please check your email for activation instructions or try resending the activation email.",
                headers={
                    "X-Account-Status": "inactive",
                    "X-Action-Required": "activation",
                    "X-User-Email": user.email,
                    "X-Email-Resent": "failed"
                }
            )
    else:
        # Token is still valid, just inform user
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not activated. Please check your email for activation instructions.",
            headers={
                "X-Account-Status": "inactive",
                "X-Action-Required": "activation", 
                "X-User-Email": user.email
            }
        )


@router.post("/login")
async def login(
    response: Response,
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
    remember_me: bool = False,
):
    user = await get_user(session, form_data.username)
    
    # Always verify password first to prevent timing attacks
    # Use a dummy hash if user doesn't exist to maintain consistent timing
    if user:
        password_valid = verify_password(form_data.password, user.password)
    else:
        # Perform dummy password verification to prevent timing attacks
        from app.core.authentication import get_password_hash
        get_password_hash("dummy_password_to_maintain_timing")
        password_valid = False
    
    # SECURE TWO-STAGE AUTHENTICATION:
    # Stage 1: Check credentials without revealing user existence
    if not user or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    
    # Stage 2: Only after valid credentials, check activation status and token expiry
    # This is SECURE because we've already verified the password
    if not user.is_active:
        from datetime import datetime, timezone, timedelta
        
        # Check if activation token is older than 48 hours or doesn't exist
        should_resend_email = False
        
        if not user.activation_token_hash or not user.activation_token_expires:
            # No activation token exists, need to create and send one
            should_resend_email = True
        else:
            # Check if token is expired (older than 48 hours)
            # Fixed timezone issue - using simple comparison
            if datetime.now(timezone.utc) > (user.activation_token_expires.replace(tzinfo=timezone.utc) if user.activation_token_expires.tzinfo is None else user.activation_token_expires):
                should_resend_email = True
        
        # Resend activation email if token is expired
        if should_resend_email:
            try:
                # Create new activation token
                activation_token = await create_activation_token(session, user.id)
                
                # Send new activation email
                await send_activation_email(
                    email=user.email,
                    username=user.username,
                    activation_token=activation_token
                )
                
                # Update response to indicate email was resent
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is not activated. A new activation email has been sent to your email address.",
                    headers={
                        "X-Account-Status": "inactive",
                        "X-Action-Required": "activation", 
                        "X-User-Email": user.email,
                        "X-Email-Resent": "true"
                    }
                )
            except Exception:
                # If email sending fails, still inform user but don't expose error
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is not activated. Please check your email for activation instructions or try resending the activation email.",
                    headers={
                        "X-Account-Status": "inactive",
                        "X-Action-Required": "activation",
                        "X-User-Email": user.email,
                        "X-Email-Resent": "failed"
                    }
                )
        else:
            # Token is still valid, just inform user
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not activated. Please check your email for activation instructions.",
                headers={
                    "X-Account-Status": "inactive",
                    "X-Action-Required": "activation", 
                    "X-User-Email": user.email
                }
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
        secure=settings.environment
        != "development",  # False for local dev, True for production
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
    
    # Always verify password first to prevent timing attacks
    # Use a dummy hash if user doesn't exist to maintain consistent timing
    if user:
        password_valid = verify_password(form_data.password, user.password)
    else:
        # Perform dummy password verification to prevent timing attacks
        from app.core.authentication import get_password_hash
        get_password_hash("dummy_password_to_maintain_timing")
        password_valid = False
    
    # SECURE TWO-STAGE AUTHENTICATION:
    # Stage 1: Check credentials without revealing user existence
    if not user or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    
    # Stage 2: Only after valid credentials, check activation status and token expiry
    # This is SECURE because we've already verified the password
    if not user.is_active:
        from datetime import datetime, timezone, timedelta
        
        # Check if activation token is older than 48 hours or doesn't exist
        should_resend_email = False
        
        if not user.activation_token_hash or not user.activation_token_expires:
            # No activation token exists, need to create and send one
            should_resend_email = True
        else:
            # Check if token is expired (older than 48 hours)
            # Fixed timezone issue - using simple comparison
            if datetime.now(timezone.utc) > (user.activation_token_expires.replace(tzinfo=timezone.utc) if user.activation_token_expires.tzinfo is None else user.activation_token_expires):
                should_resend_email = True
        
        # Resend activation email if token is expired
        if should_resend_email:
            try:
                # Create new activation token
                activation_token = await create_activation_token(session, user.id)
                
                # Send new activation email
                await send_activation_email(
                    email=user.email,
                    username=user.username,
                    activation_token=activation_token
                )
                
                # Update response to indicate email was resent
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is not activated. A new activation email has been sent to your email address.",
                    headers={
                        "X-Account-Status": "inactive",
                        "X-Action-Required": "activation", 
                        "X-User-Email": user.email,
                        "X-Email-Resent": "true"
                    }
                )
            except Exception:
                # If email sending fails, still inform user but don't expose error
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is not activated. Please check your email for activation instructions or try resending the activation email.",
                    headers={
                        "X-Account-Status": "inactive",
                        "X-Action-Required": "activation",
                        "X-User-Email": user.email,
                        "X-Email-Resent": "failed"
                    }
                )
        else:
            # Token is still valid, just inform user
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not activated. Please check your email for activation instructions.",
                headers={
                    "X-Account-Status": "inactive",
                    "X-Action-Required": "activation", 
                    "X-User-Email": user.email
                }
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
        secure=settings.environment
        != "development",  # False for local dev, True for production
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
        user.is_active = False  # User must activate via email
        session.add(user)
        await session.commit()
        await session.refresh(user)

        activation_token = await create_activation_token(session, user.id)

        # Send activation email
        await send_activation_email(
            email=user.email,
            username=user.username,
            activation_token=activation_token
        )

        return user
    except Exception as e:
        print(f"Error registering user: {e}")
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user",
        )


class ActivationRequest(BaseModel):
    token: str


@router.post("/activate")
async def activate_user(data: ActivationRequest, session: SessionDep):
    """
    Activate user account with token from their email

    Security:
    - Token must be valid
    - Token must match hash
    - One-time use only


    Args:
        data (ActivationRequest): _description_
        session (SessionDep): _description_

    Returns:
        _type_: _description_
    """

    success = await activate_user_with_token(session, data.token)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token",
        )
    return {
        "message": "User account activated successfully.",
        "status": "success",
    }
    
@router.post("/resend-activation")
async def resend_activation_email(
    session: SessionDep,
    email: str = Body(..., embed=True)
):
    """
    Resend activation email. Uses generic response to prevent user enumeration.
    Only users who know their email and that they have an account can use this.
    """
    result = await session.exec(select(User).where(User.email == email))
    user = result.first()
    
    if user and not user.is_active:
        # Generate new activation token
        activation_token = await create_activation_token(session, user.id)

        # Send activation email
        await send_activation_email(
            email=user.email,
            username=user.username,
            activation_token=activation_token
        )
        
    # Always return success message to avoid user enumeration
    # This is secure because users must already know their email exists
    return {
        "message": "If an account with that email exists and is inactive, an activation email has been sent.",
        "status": "success",
    }


@router.post("/check-activation-status")
async def check_activation_status(
    session: SessionDep,
    username: str = Body(..., embed=True),
    password: str = Body(..., embed=True)
):
    """
    Check if a user needs activation. Requires valid credentials to prevent enumeration.
    This allows UI to show activation-specific help after failed login.
    """
    user = await get_user(session, username)
    
    # Verify credentials first (same timing protection as login)
    if user:
        password_valid = verify_password(password, user.password)
    else:
        from app.core.authentication import get_password_hash
        get_password_hash("dummy_password_to_maintain_timing")
        password_valid = False
    
    # Only reveal activation status for valid credentials
    if not user or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    
    # Safe to reveal activation status since credentials are verified
    return {
        "username": user.username,
        "email": user.email,
        "is_active": user.is_active,
        "needs_activation": not user.is_active,
        "message": "Account activation required" if not user.is_active else "Account is active"
    }

@router.post("/activate/lookup")
async def activate_user_lookup(
    data: Annotated[ActivateUserRequest, Form()], session: SessionDep
):
    """
    DEPRECATED: Use /auth/activate instead
    
    This endpoint

    Args:
        data (Annotated[ActivateUserRequest, Form): _description_
        session (SessionDep): _description_

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_
    """
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
    if user.is_active:
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
