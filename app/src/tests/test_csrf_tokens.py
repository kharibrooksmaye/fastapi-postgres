"""
Tests for CSRF token management functions.
"""

import pytest
import secrets
from app.core.authentication import store_csrf_token, verify_csrf_token


@pytest.fixture
def valid_credentials():
    """Valid test user credentials"""
    return {"username": "testuser", "password": "testpassword123"}


class TestCSRFTokenManagement:
    """Tests for CSRF token storage and verification"""

    @pytest.mark.asyncio
    async def test_store_csrf_token_success(
        self, authenticated_client, valid_credentials, test_db_session
    ):
        """Test storing CSRF token with an active refresh token"""
        # Login to create a refresh token
        login_response = authenticated_client.post("/auth/login", data=valid_credentials)
        assert login_response.status_code == 200
        user_id = login_response.json()["user"]["id"]

        csrf_token = secrets.token_urlsafe(32)

        # Store CSRF token
        result = await store_csrf_token(test_db_session, user_id, csrf_token)
        assert result is True

        # Verify it was stored
        is_valid = await verify_csrf_token(test_db_session, user_id, csrf_token)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_store_csrf_token_no_refresh_token(
        self, authenticated_client, test_db_session
    ):
        """Test storing CSRF token fails when no refresh token exists"""
        non_existent_user_id = 99999
        csrf_token = secrets.token_urlsafe(32)

        result = await store_csrf_token(test_db_session, non_existent_user_id, csrf_token)
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_csrf_token_valid(
        self, authenticated_client, valid_credentials, test_db_session
    ):
        """Test verifying a valid CSRF token"""
        login_response = authenticated_client.post("/auth/login", data=valid_credentials)
        user_id = login_response.json()["user"]["id"]

        csrf_token = secrets.token_urlsafe(32)

        # Store then verify
        await store_csrf_token(test_db_session, user_id, csrf_token)
        is_valid = await verify_csrf_token(test_db_session, user_id, csrf_token)

        assert is_valid is True

    @pytest.mark.asyncio
    async def test_verify_csrf_token_invalid(
        self, authenticated_client, valid_credentials, test_db_session
    ):
        """Test verifying an invalid CSRF token returns False"""
        login_response = authenticated_client.post("/auth/login", data=valid_credentials)
        user_id = login_response.json()["user"]["id"]

        valid_csrf = secrets.token_urlsafe(32)
        invalid_csrf = secrets.token_urlsafe(32)

        await store_csrf_token(test_db_session, user_id, valid_csrf)
        is_valid = await verify_csrf_token(test_db_session, user_id, invalid_csrf)

        assert is_valid is False

    @pytest.mark.asyncio
    async def test_verify_csrf_token_no_token_stored(
        self, authenticated_client, valid_credentials, test_db_session
    ):
        """Test verifying CSRF token when none is stored returns False"""
        login_response = authenticated_client.post("/auth/login", data=valid_credentials)
        user_id = login_response.json()["user"]["id"]

        csrf_token = secrets.token_urlsafe(32)

        # Don't store, just try to verify
        is_valid = await verify_csrf_token(test_db_session, user_id, csrf_token)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_verify_csrf_token_no_user(self, authenticated_client, test_db_session):
        """Test verifying CSRF token for non-existent user returns False"""
        non_existent_user_id = 99999
        csrf_token = secrets.token_urlsafe(32)

        is_valid = await verify_csrf_token(test_db_session, non_existent_user_id, csrf_token)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_csrf_token_uses_most_recent_refresh_token(
        self, authenticated_client, valid_credentials, test_db_session
    ):
        """Test that CSRF token is associated with most recent refresh token"""
        # Login twice to create two refresh tokens
        login1 = authenticated_client.post("/auth/login", data=valid_credentials)
        login2 = authenticated_client.post("/auth/login", data=valid_credentials)

        user_id = login1.json()["user"]["id"]
        csrf_token = secrets.token_urlsafe(32)

        # Store CSRF token (should use most recent)
        await store_csrf_token(test_db_session, user_id, csrf_token)

        # Verify it works
        is_valid = await verify_csrf_token(test_db_session, user_id, csrf_token)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_csrf_token_update_overwrites_previous(
        self, authenticated_client, valid_credentials, test_db_session
    ):
        """Test that storing a new CSRF token overwrites the previous one"""
        login_response = authenticated_client.post("/auth/login", data=valid_credentials)
        user_id = login_response.json()["user"]["id"]

        first_csrf = secrets.token_urlsafe(32)
        second_csrf = secrets.token_urlsafe(32)

        # Store first, then second (overwrites)
        await store_csrf_token(test_db_session, user_id, first_csrf)
        await store_csrf_token(test_db_session, user_id, second_csrf)

        # First should be invalid
        is_first_valid = await verify_csrf_token(test_db_session, user_id, first_csrf)
        assert is_first_valid is False

        # Second should be valid
        is_second_valid = await verify_csrf_token(test_db_session, user_id, second_csrf)
        assert is_second_valid is True
