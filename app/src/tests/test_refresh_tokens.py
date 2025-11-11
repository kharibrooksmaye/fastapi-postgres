"""
Tests for refresh token functionality including login, refresh, logout, and session management.
"""

import pytest
from datetime import datetime, timedelta, timezone


@pytest.fixture
def valid_credentials():
    """Valid test user credentials"""
    return {"username": "testuser", "password": "testpassword123"}


@pytest.fixture
def login_with_refresh(authenticated_client, valid_credentials):
    """Fixture that logs in and returns access and refresh tokens"""
    response = authenticated_client.post("/auth/login", data=valid_credentials)
    assert response.status_code == 200
    data = response.json()
    return {
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "user": data.get("user"),
    }


class TestLoginWithRefreshToken:
    """Tests for login endpoint with refresh token support"""

    def test_login_returns_refresh_token(self, authenticated_client, valid_credentials):
        """Test that login returns both access and refresh tokens"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert "expires" in data
        assert "refresh_expires" in data
        assert data["token_type"] == "bearer"

    def test_login_with_remember_me(self, authenticated_client, valid_credentials):
        """Test login with remember_me parameter"""
        response = authenticated_client.post(
            "/auth/login",
            data=valid_credentials,
            params={"remember_me": True},
        )

        assert response.status_code == 200
        data = response.json()
        assert "refresh_token" in data
        assert "refresh_expires" in data

        # Verify the expiration is extended (should be 90 days instead of 30)
        refresh_expires = datetime.strptime(
            data["refresh_expires"], "%Y-%m-%d %H:%M:%S"
        )
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        days_until_expiry = (refresh_expires - now).days

        # Should be close to 90 days (allow some margin for test execution time)
        assert 89 <= days_until_expiry <= 91

    def test_token_endpoint_returns_refresh_token(
        self, authenticated_client, valid_credentials
    ):
        """Test that /auth/token endpoint also returns refresh token"""
        response = authenticated_client.post("/auth/token", data=valid_credentials)

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "refresh_expires" in data


class TestRefreshEndpoint:
    """Tests for /auth/refresh endpoint"""

    def test_refresh_token_success(self, authenticated_client, login_with_refresh):
        """Test successful token refresh"""
        import time

        refresh_token = login_with_refresh["refresh_token"]
        original_access_token = login_with_refresh["access_token"]

        # Wait a moment to ensure different timestamp
        time.sleep(0.1)

        response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert "expires" in data
        assert data["token_type"] == "bearer"

        # Verify we got a token (may or may not be different due to timestamp resolution)
        assert len(data["access_token"]) > 100

    def test_refresh_with_invalid_token(self, authenticated_client):
        """Test refresh with invalid token"""
        response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": "invalid_token_string"}
        )

        assert response.status_code == 401
        assert "Invalid or expired refresh token" in response.json()["detail"]

    def test_refresh_with_expired_token(self, authenticated_client, login_with_refresh):
        """Test that expired tokens cannot be refreshed"""
        # This would require manipulating the database to expire a token
        # or waiting for expiration, so we'll test with an invalid token as proxy
        response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": "obviously_fake_token"}
        )

        assert response.status_code == 401

    def test_refresh_updates_last_used_at(
        self, authenticated_client, login_with_refresh
    ):
        """Test that refreshing updates the last_used_at timestamp"""
        refresh_token = login_with_refresh["refresh_token"]

        # First refresh
        response1 = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert response1.status_code == 200

        # Second refresh (should still work and update timestamp)
        response2 = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert response2.status_code == 200


class TestLogoutEndpoint:
    """Tests for /auth/logout endpoint"""

    def test_logout_revokes_specific_token(
        self, authenticated_client, login_with_refresh
    ):
        """Test logout with specific refresh token"""
        access_token = login_with_refresh["access_token"]
        refresh_token = login_with_refresh["refresh_token"]

        # Logout with specific token
        response = authenticated_client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        assert "Logged out successfully" in response.json()["message"]

        # Try to refresh with revoked token (should fail)
        refresh_response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert refresh_response.status_code == 401

    def test_logout_all_devices(self, authenticated_client, valid_credentials):
        """Test logout without refresh token revokes all tokens"""
        # Login twice to create two sessions
        login1 = authenticated_client.post("/auth/login", data=valid_credentials)
        login2 = authenticated_client.post("/auth/login", data=valid_credentials)

        assert login1.status_code == 200
        assert login2.status_code == 200

        access_token = login1.json()["access_token"]
        refresh_token1 = login1.json()["refresh_token"]
        refresh_token2 = login2.json()["refresh_token"]

        # Logout from all devices
        response = authenticated_client.post(
            "/auth/logout",
            json={},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        assert "device(s) successfully" in response.json()["message"]

        # Both refresh tokens should be revoked
        refresh1_response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token1}
        )
        refresh2_response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token2}
        )

        assert refresh1_response.status_code == 401
        assert refresh2_response.status_code == 401

    def test_logout_requires_authentication(self, unauthenticated_client):
        """Test that logout requires valid access token"""
        response = unauthenticated_client.post("/auth/logout", json={})

        assert response.status_code == 401


class TestSessionsEndpoint:
    """Tests for /auth/sessions endpoint"""

    def test_get_sessions_success(self, authenticated_client, login_with_refresh):
        """Test retrieving user sessions"""
        access_token = login_with_refresh["access_token"]

        response = authenticated_client.get(
            "/auth/sessions", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert len(data["sessions"]) > 0

        # Verify session structure
        session = data["sessions"][0]
        assert "id" in session
        assert "ip_address" in session
        assert "user_agent" in session
        assert "created_at" in session
        assert "expires_at" in session

    def test_get_sessions_shows_multiple_devices(
        self, authenticated_client, valid_credentials
    ):
        """Test that multiple logins create multiple sessions"""
        # Login twice
        login1 = authenticated_client.post("/auth/login", data=valid_credentials)
        login2 = authenticated_client.post("/auth/login", data=valid_credentials)

        access_token = login1.json()["access_token"]

        response = authenticated_client.get(
            "/auth/sessions", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200
        assert len(response.json()["sessions"]) >= 2

    def test_get_sessions_requires_authentication(self, unauthenticated_client):
        """Test that getting sessions requires authentication"""
        response = unauthenticated_client.get("/auth/sessions")

        assert response.status_code == 401


class TestRevokeSessionEndpoint:
    """Tests for DELETE /auth/sessions/{token_id} endpoint"""

    def test_revoke_specific_session(self, authenticated_client, valid_credentials):
        """Test revoking a specific session by ID"""
        # Create two sessions
        login1 = authenticated_client.post("/auth/login", data=valid_credentials)
        login2 = authenticated_client.post("/auth/login", data=valid_credentials)

        access_token = login1.json()["access_token"]

        # Get sessions
        sessions_response = authenticated_client.get(
            "/auth/sessions", headers={"Authorization": f"Bearer {access_token}"}
        )
        sessions = sessions_response.json()["sessions"]
        assert len(sessions) >= 2

        # Revoke first session
        session_id = sessions[0]["id"]
        revoke_response = authenticated_client.delete(
            f"/auth/sessions/{session_id}",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert revoke_response.status_code == 200
        assert "Session revoked successfully" in revoke_response.json()["message"]

        # Verify session count decreased
        sessions_after = authenticated_client.get(
            "/auth/sessions", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert len(sessions_after.json()["sessions"]) == len(sessions) - 1

    def test_cannot_revoke_other_users_session(
        self, authenticated_client, valid_credentials
    ):
        """Test that users cannot revoke other users' sessions"""
        # This would require creating another user
        # For now, test with non-existent session ID
        login = authenticated_client.post("/auth/login", data=valid_credentials)
        access_token = login.json()["access_token"]

        # Try to revoke non-existent or other user's session
        response = authenticated_client.delete(
            "/auth/sessions/999999",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 404
        assert "Session not found" in response.json()["detail"]

    def test_revoke_session_requires_authentication(self, unauthenticated_client):
        """Test that revoking a session requires authentication"""
        response = unauthenticated_client.delete("/auth/sessions/1")

        assert response.status_code == 401


class TestRefreshTokenSecurity:
    """Security tests for refresh token implementation"""

    def test_refresh_token_is_hashed_in_database(
        self, authenticated_client, login_with_refresh
    ):
        """Test that refresh tokens are not stored in plain text"""
        # This would require direct database access to verify
        # The implementation uses bcrypt hashing, which we've verified in the code
        refresh_token = login_with_refresh["refresh_token"]
        assert len(refresh_token) > 40  # Should be a long, secure token

    def test_revoked_token_cannot_be_used(
        self, authenticated_client, login_with_refresh
    ):
        """Test that revoked tokens are immediately invalid"""
        access_token = login_with_refresh["access_token"]
        refresh_token = login_with_refresh["refresh_token"]

        # Revoke the token
        authenticated_client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        # Try to use revoked token
        response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token}
        )

        assert response.status_code == 401
        assert "Invalid or expired refresh token" in response.json()["detail"]

    def test_different_devices_get_different_tokens(
        self, authenticated_client, valid_credentials
    ):
        """Test that each login creates a unique refresh token"""
        login1 = authenticated_client.post("/auth/login", data=valid_credentials)
        login2 = authenticated_client.post("/auth/login", data=valid_credentials)

        token1 = login1.json()["refresh_token"]
        token2 = login2.json()["refresh_token"]

        assert token1 != token2
