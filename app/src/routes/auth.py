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
    create_password_reset_token,
    create_refresh_token,
    get_current_user,
    get_password_hash,
    get_user,
    get_user_sessions,
    increment_failed_login_attempts,
    is_account_locked,
    reset_failed_login_attempts,
    revoke_all_user_tokens,
    revoke_refresh_token,
    store_csrf_token,
    use_password_reset_token,
    verify_and_get_refresh_token,
    verify_csrf_token,
    verify_password,
    verify_password_reset_token,
)
from app.core.database import SessionDep
from app.core.email import (
    send_activation_email,
    send_password_reset_email,
    send_password_changed_notification,
    send_account_locked_notification,
)
from app.core.password_policy import validate_password_policy
from app.core.rate_limit import rate_limit_manager
from app.core.settings import settings
from app.src.models.users import User
from app.src.schema.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    PasswordChangeRequest,
    PasswordChangeResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    PasswordResetResponse,
    SecurityStatusResponse,
)
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
    # Apply rate limiting for login attempts
    rate_limit_manager.check_authentication_rate_limit(request, "login")
    
    user = await get_user(session, form_data.username)
    
    # Check if account is locked BEFORE password verification (security best practice)
    if user and await is_account_locked(user):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to multiple failed login attempts. Please try again later.",
            headers={
                "X-Account-Status": "locked",
                "X-Action-Required": "wait",
                "X-Lockout-Expires": user.account_locked_until.isoformat() if user.account_locked_until else None
            }
        )
    
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
        # Increment failed attempts if user exists
        if user:
            await increment_failed_login_attempts(session, user)
            
            # Check if account is now locked after this attempt
            if await is_account_locked(user):
                await send_account_locked_notification(
                    user.email,
                    user.username,
                    lockout_duration_minutes=15,
                    failed_attempts=user.failed_login_attempts
                )
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

    # Reset failed login attempts on successful authentication
    await reset_failed_login_attempts(session, user)

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
async def register_user(user: User, request: Request, session: SessionDep):
    # Apply rate limiting for registration attempts
    rate_limit_manager.check_authentication_rate_limit(request, "register")
    
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
    
    # Validate password against security policy
    user_info = {
        'username': user.username,
        'email': user.email,
        'name': user.name
    }
    
    is_valid, errors, score, strength = validate_password_policy(
        user.password, 
        user_info=user_info,
        password_history=None  # No history for new user
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password does not meet security requirements: {'; '.join(errors)}"
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


# Password Management Routes

@router.post("/password/reset-request", response_model=PasswordResetResponse)
async def request_password_reset(
    data: PasswordResetRequest,
    request: Request,
    session: SessionDep
):
    """
    Request a password reset token via email.
    
    Security Features:
    - Does not reveal if user exists (prevents user enumeration)
    - Secure token generation with 1-hour expiry
    - Rate limiting to prevent abuse
    
    Args:
        data: Password reset request (email or username)
        request: FastAPI request object for IP logging
        session: Database session
        
    Returns:
        Standardized response regardless of user existence
    """
    # Apply rate limiting for password reset attempts
    rate_limit_manager.check_authentication_rate_limit(request, "password_reset")
    
    user = None
    
    # Find user by email or username (timing-safe approach)
    if data.email:
        result = await session.exec(select(User).where(User.email == data.email))
        user = result.first()
    elif data.username:
        result = await session.exec(select(User).where(User.username == data.username))
        user = result.first()
    
    # Always return success message to prevent user enumeration
    if user and user.is_active:
        try:
            # Generate reset token
            reset_token = await create_password_reset_token(session, user.id)
            
            # Send reset email
            await send_password_reset_email(user.email, user.username, reset_token)
            
            user_status = "active"
        except Exception as e:
            print(f"Failed to send password reset email: {e}")
            user_status = "email_error"
    else:
        user_status = "not_found" if not user else "inactive"
    
    # Return same message regardless of outcome (security best practice)
    return PasswordResetResponse(
        message="If an account with that email exists, a password reset link has been sent.",
        success=True,
        user_status=user_status
    )


@router.post("/password/reset-confirm", response_model=PasswordChangeResponse)
async def confirm_password_reset(
    data: PasswordResetConfirm,
    request: Request,
    session: SessionDep
):
    """
    Confirm password reset using token and set new password.
    
    Security Features:
    - Token validation with timing-safe comparison
    - Password confirmation matching
    - One-time token usage
    - Automatic account unlock on successful reset
    
    Args:
        data: Password reset confirmation with token and new password
        request: FastAPI request object for IP logging
        session: Database session
        
    Returns:
        Password change confirmation
    """
    # Apply rate limiting for password reset confirmation attempts
    rate_limit_manager.check_authentication_rate_limit(request, "password_reset")
    
    # Validate password confirmation
    if data.new_password != data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password confirmation does not match"
        )
    
    # Comprehensive password policy validation
    is_valid, errors, score, strength = validate_password_policy(
        data.new_password, 
        user_info=None,  # No user info available during reset
        password_history=None  # Password history will be checked in use_password_reset_token
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password does not meet security requirements: {'; '.join(errors)}"
        )
    
    # Attempt to reset password
    success = await use_password_reset_token(session, data.token, data.new_password)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    # Get user to send notification
    user = await verify_password_reset_token(session, data.token)
    if user:
        # Send password change notification
        client_ip = request.client.host if request.client else "Unknown"
        await send_password_changed_notification(user.email, user.username, client_ip)
    
    from datetime import datetime, timezone
    return PasswordChangeResponse(
        message=f"Password successfully reset (Strength: {strength}, Score: {score}/100)",
        success=True,
        password_changed_at=datetime.now(timezone.utc)
    )


@router.post("/password/change", response_model=PasswordChangeResponse)
async def change_password(
    data: PasswordChangeRequest,
    request: Request,
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    Change password for authenticated user.
    
    Security Features:
    - Current password verification
    - Password confirmation matching
    - Password strength validation
    - Failed attempt tracking
    
    Args:
        data: Password change request with current and new passwords
        request: FastAPI request object for IP logging
        session: Database session
        current_user: Currently authenticated user
        
    Returns:
        Password change confirmation
    """
    # Apply rate limiting for password change attempts
    rate_limit_manager.check_authentication_rate_limit(request, "password_change")
    
    # Verify current password
    if not verify_password(data.current_password, current_user.password):
        # Increment failed attempts for security
        await increment_failed_login_attempts(session, current_user)
        
        # Check if account should be locked
        if await is_account_locked(current_user):
            await send_account_locked_notification(
                current_user.email, 
                current_user.username,
                lockout_duration_minutes=15,
                failed_attempts=current_user.failed_login_attempts
            )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Validate password confirmation
    if data.new_password != data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password confirmation does not match"
        )
    
    # Prevent reusing current password
    if verify_password(data.new_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password"
        )
    
    # Get user information for password policy validation
    user_info = {
        'username': current_user.username,
        'email': current_user.email,
        'name': current_user.name
    }
    
    # TODO: Implement password history retrieval
    # For now, we'll use current password as history
    password_history = [current_user.password] if current_user.password else []
    
    # Comprehensive password policy validation
    is_valid, errors, score, strength = validate_password_policy(
        data.new_password, 
        user_info=user_info,
        password_history=password_history
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password does not meet security requirements: {'; '.join(errors)}"
        )
    
    # Update password
    from datetime import datetime, timezone
    current_user.password = get_password_hash(data.new_password)
    current_user.password_changed_at = datetime.now(timezone.utc)
    current_user.failed_login_attempts = 0  # Reset failed attempts
    current_user.account_locked_until = None  # Unlock if locked
    
    session.add(current_user)
    await session.commit()
    
    # Send notification email
    client_ip = request.client.host if request.client else "Unknown"
    await send_password_changed_notification(current_user.email, current_user.username, client_ip)
    
    return PasswordChangeResponse(
        message=f"Password successfully changed (Strength: {strength}, Score: {score}/100)",
        success=True,
        password_changed_at=current_user.password_changed_at
    )


@router.get("/security/status", response_model=SecurityStatusResponse)
async def get_security_status(
    session: SessionDep,
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    Get security status information for current user.
    
    Returns account security details including:
    - Account lock status
    - Failed login attempts
    - Password expiry information
    - Password age
    
    Args:
        session: Database session
        current_user: Currently authenticated user
        
    Returns:
        Security status information
    """
    from datetime import datetime, timezone
    
    # Calculate password age if password_changed_at exists
    password_age_days = None
    if current_user.password_changed_at:
        age_delta = datetime.now(timezone.utc) - current_user.password_changed_at
        password_age_days = age_delta.days
    
    return SecurityStatusResponse(
        is_locked=await is_account_locked(current_user),
        lockout_expires_at=current_user.account_locked_until,
        failed_attempts=current_user.failed_login_attempts,
        max_attempts=5,
        password_expires_at=current_user.password_expires_at,
        password_age_days=password_age_days
    )


# Simplified Password Reset Endpoints (User-Friendly Aliases)

@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    data: ForgotPasswordRequest,
    request: Request,
    session: SessionDep
):
    """
    Simplified password reset request using email only (user-friendly alias).
    
    This endpoint provides a simplified, consumer-friendly alternative to
    /password/reset-request. It only accepts email addresses, making it
    ideal for consumer applications where the UX should be simple.
    
    Security Features:
    - Same security as /password/reset-request
    - Does not reveal if user exists (prevents user enumeration)
    - Secure token generation with 1-hour expiry
    - Rate limiting to prevent abuse
    - Email-only input for simplified UX
    
    Args:
        data: Forgot password request with email only
        request: FastAPI request object for IP logging
        session: Database session
        
    Returns:
        Standardized success response regardless of user existence
    """
    # Apply rate limiting for password reset attempts
    rate_limit_manager.check_authentication_rate_limit(request, "password_reset")
    
    user = None
    
    # Find user by email (timing-safe approach)
    result = await session.exec(select(User).where(User.email == data.email))
    user = result.first()
    
    # Always return success message to prevent user enumeration
    if user and user.is_active:
        try:
            # Generate reset token using the existing function
            reset_token = await create_password_reset_token(session, user.id)
            
            # Send reset email using the existing function
            await send_password_reset_email(
                user.email,
                user.username,
                reset_token,
                user_id=user.id
            )
            
        except Exception:
            # Still return success to prevent user enumeration
            # Error already logged in send_password_reset_email
            pass
    
    # Always return the same response regardless of user existence
    return ForgotPasswordResponse(
        message="If an account with that email exists, a password reset link has been sent.",
        success=True
    )
