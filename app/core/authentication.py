from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
import secrets
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Session, select

from app.core.database import SessionDep
from app.core.settings import settings
from app.src.models.users import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


async def get_user(db: Session, username: str):
    result = await db.exec(select(User).where(User.username == username))
    user = result.first()
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if "sub" not in to_encode:
        raise ValueError("Token payload must include 'sub' (username)")
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=4)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm
    )
    expire_string = expire.strftime("%Y-%m-%d %H:%M:%S")
    return {"access_token": encoded_jwt, "expires": expire_string}


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


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], db: SessionDep
) -> User:
    username = verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await get_user(db, username=username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please activate your account. Check your email for the activation link"
        )
    return user


# Refresh Token Functions


def generate_refresh_token() -> str:
    """
    Generate a cryptographically secure random refresh token.
    Returns a URL-safe 64-character token.
    """
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """
    Hash a refresh token for secure storage in the database.
    Uses bcrypt for consistent hashing with password hashing.
    """
    return pwd_context.hash(token)


def verify_refresh_token(token: str, token_hash: str) -> bool:
    """
    Verify a refresh token against its stored hash.
    """
    return pwd_context.verify(token, token_hash)


async def create_refresh_token(
    db: Session,
    user_id: int,
    request: Request,
    remember_me: bool = False,
) -> tuple[str, datetime]:
    """
    Create a new refresh token for a user.

    Args:
        db: Database session
        user_id: ID of the user
        request: FastAPI request object for extracting device info
        remember_me: If True, use extended expiration time

    Returns:
        Tuple of (token_string, expiration_datetime)
    """
    # Import here to avoid circular dependency
    from app.src.models.refresh_tokens import RefreshToken

    # Generate token
    token = generate_refresh_token()
    token_hash = hash_token(token)

    # Determine expiration
    if remember_me:
        expire_days = settings.refresh_token_remember_me_days
    else:
        expire_days = settings.refresh_token_expire_days

    expires_at = datetime.now(timezone.utc) + timedelta(days=expire_days)

    # Extract device information
    user_agent = request.headers.get("user-agent", "")[:512]
    # Get real IP even behind proxy
    ip_address = request.headers.get("x-forwarded-for", request.client.host if request.client else None)
    if ip_address and "," in ip_address:
        ip_address = ip_address.split(",")[0].strip()

    # Create refresh token record
    refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
    )

    db.add(refresh_token)
    await db.commit()
    await db.refresh(refresh_token)

    return token, expires_at


async def verify_and_get_refresh_token(db: Session, token: str):
    """
    Verify a refresh token and return the associated token record.

    Args:
        db: Database session
        token: The refresh token string

    Returns:
        RefreshToken object if valid, None otherwise
    """
    # Import here to avoid circular dependency
    from app.src.models.refresh_tokens import RefreshToken

    # Get all non-revoked, non-expired tokens
    result = await db.exec(
        select(RefreshToken).where(
            RefreshToken.is_revoked.is_(False),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    tokens = result.all()

    # Check each token hash
    for token_record in tokens:
        if verify_refresh_token(token, token_record.token_hash):
            # Update last_used_at
            token_record.last_used_at = datetime.now(timezone.utc)
            db.add(token_record)
            await db.commit()
            await db.refresh(token_record)
            return token_record

    return None


async def revoke_refresh_token(db: Session, token_id: int) -> bool:
    """
    Revoke a refresh token by its ID.

    Args:
        db: Database session
        token_id: ID of the refresh token to revoke

    Returns:
        True if revoked successfully, False if not found
    """
    # Import here to avoid circular dependency
    from app.src.models.refresh_tokens import RefreshToken

    result = await db.exec(select(RefreshToken).where(RefreshToken.id == token_id))
    token = result.first()

    if not token:
        return False

    token.is_revoked = True
    token.revoked_at = datetime.now(timezone.utc)
    db.add(token)
    await db.commit()
    return True


async def revoke_all_user_tokens(db: Session, user_id: int) -> int:
    """
    Revoke all refresh tokens for a user.

    Args:
        db: Database session
        user_id: ID of the user

    Returns:
        Number of tokens revoked
    """
    # Import here to avoid circular dependency
    from app.src.models.refresh_tokens import RefreshToken

    result = await db.exec(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.is_revoked.is_(False)
        )
    )
    tokens = result.all()

    count = 0
    for token in tokens:
        token.is_revoked = True
        token.revoked_at = datetime.now(timezone.utc)
        db.add(token)
        count += 1

    await db.commit()
    return count


async def get_user_sessions(db: Session, user_id: int):
    """
    Get all active refresh token sessions for a user.

    Args:
        db: Database session
        user_id: ID of the user

    Returns:
        List of active RefreshToken objects
    """
    # Import here to avoid circular dependency
    from app.src.models.refresh_tokens import RefreshToken

    result = await db.exec(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked.is_(False),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    return result.all()


# CSRF Token Management


async def store_csrf_token(db: Session, user_id: int, csrf_token: str) -> bool:
    """
    Store a hashed CSRF token with the user's most recent refresh token.

    This links the CSRF token to the refresh token for validation during
    token refresh operations. The CSRF token is hashed before storage.

    Args:
        db: Database session
        user_id: User ID
        csrf_token: Plain CSRF token to hash and store

    Returns:
        True if stored successfully, False if no active refresh token found
    """
    # Import here to avoid circular dependency
    from app.src.models.refresh_tokens import RefreshToken

    # Get the most recent non-revoked refresh token for this user
    result = await db.exec(
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user_id, RefreshToken.is_revoked.is_(False)
        )
        .order_by(RefreshToken.created_at.desc())
    )
    token = result.first()

    if not token:
        return False

    # Hash and store the CSRF token
    token.csrf_token_hash = hash_token(csrf_token)
    db.add(token)
    await db.commit()
    return True


async def verify_csrf_token(db: Session, user_id: int, csrf_token: str) -> bool:
    """
    Verify a CSRF token against the stored hash for a user.

    Checks the most recent non-revoked refresh token's CSRF hash.

    Args:
        db: Database session
        user_id: User ID
        csrf_token: Plain CSRF token to verify

    Returns:
        True if valid, False otherwise
    """
    # Import here to avoid circular dependency
    from app.src.models.refresh_tokens import RefreshToken

    # Get the most recent non-revoked refresh token
    result = await db.exec(
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user_id, RefreshToken.is_revoked.is_(False)
        )
        .order_by(RefreshToken.created_at.desc())
    )
    token = result.first()

    if not token or not token.csrf_token_hash:
        return False

    # Verify the CSRF token against the stored hash
    return pwd_context.verify(csrf_token, token.csrf_token_hash)
