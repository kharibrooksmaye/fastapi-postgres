import pytest
from datetime import timedelta
from unittest.mock import AsyncMock, Mock
from fastapi import HTTPException
from jose import jwt

from app.core.authentication import (
    get_password_hash,
    verify_password,
    get_user,
    create_access_token,
    verify_token,
    get_current_user,
)
from app.src.models.users import User
from app.src.schema.users import UserTypeEnum


@pytest.fixture
def mock_user():
    """Create a mock user for testing"""
    return User(
        id=1,
        name="Test User",
        member_id="1",
        username="testuser",
        email="test@example.com",
        password="$2b$12$NxBnVDJB/IbsFlbGIYMVOOTGk5WpQNmc.RnV31HTcXKOBr72fkrmO",
        is_active=True,
        type=UserTypeEnum.admin
    )


@pytest.fixture
def mock_session():
    """Create a mock database session"""
    session = AsyncMock()
    return session


def test_get_password_hash():
    """Test password hashing"""
    password = "testpassword123"
    hashed = get_password_hash(password)

    assert hashed is not None
    assert isinstance(hashed, str)
    assert hashed != password
    assert hashed.startswith("$2b$")


def test_get_password_hash_different_passwords_produce_different_hashes():
    """Test that different passwords produce different hashes"""
    password1 = "password123"
    password2 = "password456"

    hash1 = get_password_hash(password1)
    hash2 = get_password_hash(password2)

    assert hash1 != hash2


def test_get_password_hash_same_password_produces_different_hashes():
    """Test that same password produces different hashes (due to salt)"""
    password = "testpassword"

    hash1 = get_password_hash(password)
    hash2 = get_password_hash(password)

    assert hash1 != hash2


def test_verify_password_correct():
    """Test password verification with correct password"""
    password = "testpassword123"
    hashed = get_password_hash(password)

    assert verify_password(password, hashed) is True


def test_verify_password_incorrect():
    """Test password verification with incorrect password"""
    password = "testpassword123"
    wrong_password = "wrongpassword"
    hashed = get_password_hash(password)

    assert verify_password(wrong_password, hashed) is False


def test_verify_password_empty_password():
    """Test password verification with empty password"""
    password = "testpassword123"
    hashed = get_password_hash(password)

    assert verify_password("", hashed) is False


@pytest.mark.parametrize("password", [
    "short",
    "verylongpasswordwithmanymanycharacters123456789",
    "P@ssw0rd!#$%",
    "password with spaces",
])
def test_password_hash_and_verify_various_formats(password):
    """Test hashing and verification with various password formats"""
    hashed = get_password_hash(password)
    assert verify_password(password, hashed) is True
    assert verify_password(password + "x", hashed) is False


async def test_get_user_found(mock_session, mock_user):
    """Test getting user from database - user found"""
    mock_result = Mock()
    mock_result.first.return_value = mock_user
    mock_session.exec = AsyncMock(return_value=mock_result)

    user = await get_user(mock_session, "testuser")

    assert user is not None
    assert user.username == "testuser"
    assert user.id == 1


async def test_get_user_not_found(mock_session):
    """Test getting user from database - user not found"""
    mock_result = Mock()
    mock_result.first.return_value = None
    mock_session.exec = AsyncMock(return_value=mock_result)

    user = await get_user(mock_session, "nonexistent")

    assert user is None


def test_create_access_token_default_expiry():
    """Test creating access token with default expiry"""
    data = {"sub": "testuser"}

    result = create_access_token(data)

    assert "access_token" in result
    assert "expires" in result
    assert isinstance(result["access_token"], str)
    assert isinstance(result["expires"], str)


def test_create_access_token_custom_expiry():
    """Test creating access token with custom expiry"""
    data = {"sub": "testuser"}
    expires_delta = timedelta(hours=1)

    result = create_access_token(data, expires_delta)

    assert "access_token" in result
    assert "expires" in result


def test_create_access_token_missing_sub():
    """Test creating access token without 'sub' field raises ValueError"""
    data = {"user": "testuser"}

    with pytest.raises(ValueError) as exc_info:
        create_access_token(data)

    assert "Token payload must include 'sub'" in str(exc_info.value)


def test_create_access_token_includes_additional_data():
    """Test creating access token with additional data"""
    data = {"sub": "testuser", "role": "admin", "email": "test@example.com"}

    result = create_access_token(data)

    assert "access_token" in result

    from app.core.settings import settings
    decoded = jwt.decode(
        result["access_token"],
        settings.secret_key,
        algorithms=[settings.algorithm]
    )
    assert decoded["sub"] == "testuser"
    assert decoded["role"] == "admin"
    assert decoded["email"] == "test@example.com"
    assert "exp" in decoded


def test_verify_token_valid():
    """Test verifying a valid token"""
    data = {"sub": "testuser"}
    token_data = create_access_token(data)
    token = token_data["access_token"]

    username = verify_token(token)

    assert username == "testuser"


def test_verify_token_invalid():
    """Test verifying an invalid token"""
    invalid_token = "invalid.token.string"

    username = verify_token(invalid_token)

    assert username is None


def test_verify_token_expired():
    """Test verifying an expired token"""
    data = {"sub": "testuser"}
    expires_delta = timedelta(seconds=-1)
    token_data = create_access_token(data, expires_delta)
    token = token_data["access_token"]

    username = verify_token(token)

    assert username is None


def test_verify_token_missing_sub():
    """Test verifying token without 'sub' field"""
    from app.core.settings import settings
    from datetime import datetime, timezone

    to_encode = {"user": "testuser", "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
    token = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

    username = verify_token(token)

    assert username is None


def test_verify_token_malformed():
    """Test verifying malformed token"""
    malformed_tokens = [
        "",
        "not.a.token",
        "too.short",
        "a" * 100,
    ]

    for token in malformed_tokens:
        username = verify_token(token)
        assert username is None


async def test_get_current_user_success(mock_session, mock_user):
    """Test getting current user with valid token"""
    data = {"sub": "testuser"}
    token_data = create_access_token(data)
    token = token_data["access_token"]

    mock_result = Mock()
    mock_result.first.return_value = mock_user
    mock_session.exec = AsyncMock(return_value=mock_result)

    user = await get_current_user(token, mock_session)

    assert user is not None
    assert user.username == "testuser"
    assert user.id == 1


async def test_get_current_user_invalid_token(mock_session):
    """Test getting current user with invalid token"""
    invalid_token = "invalid.token.string"

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(invalid_token, mock_session)

    assert exc_info.value.status_code == 401
    assert "Invalid authentication credentials" in exc_info.value.detail


async def test_get_current_user_user_not_found(mock_session):
    """Test getting current user when user doesn't exist in database"""
    data = {"sub": "nonexistent"}
    token_data = create_access_token(data)
    token = token_data["access_token"]

    mock_result = Mock()
    mock_result.first.return_value = None
    mock_session.exec = AsyncMock(return_value=mock_result)

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token, mock_session)

    assert exc_info.value.status_code == 401
    assert "User not found" in exc_info.value.detail


async def test_get_current_user_expired_token(mock_session):
    """Test getting current user with expired token"""
    data = {"sub": "testuser"}
    expires_delta = timedelta(seconds=-1)
    token_data = create_access_token(data, expires_delta)
    token = token_data["access_token"]

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token, mock_session)

    assert exc_info.value.status_code == 401
    assert "Invalid authentication credentials" in exc_info.value.detail


def test_create_access_token_expiry_format():
    """Test that token expiry is formatted correctly"""
    data = {"sub": "testuser"}

    result = create_access_token(data)

    expires_string = result["expires"]
    from datetime import datetime
    parsed_time = datetime.strptime(expires_string, "%Y-%m-%d %H:%M:%S")

    assert isinstance(parsed_time, datetime)


@pytest.mark.parametrize("username", [
    "user1",
    "admin",
    "test@example.com",
    "user_with_underscore",
])
async def test_get_user_various_usernames(mock_session, username):
    """Test getting users with various username formats"""
    mock_user = User(
        id=1,
        name="Test",
        member_id="1",
        username=username,
        email="test@example.com",
        password="hashed",
        is_active=True,
        type=UserTypeEnum.patron
    )

    mock_result = Mock()
    mock_result.first.return_value = mock_user
    mock_session.exec = AsyncMock(return_value=mock_result)

    user = await get_user(mock_session, username)

    assert user is not None
    assert user.username == username
