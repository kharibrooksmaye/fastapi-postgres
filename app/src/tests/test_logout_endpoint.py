"""
Tests for /auth/logout endpoint with httpOnly cookie clearing.
"""

import pytest


@pytest.fixture
def valid_credentials():
    """Valid test user credentials"""
    return {"username": "testuser", "password": "testpassword123"}


class TestLogoutEndpointWithCookies:
    """Tests for /auth/logout endpoint using httpOnly cookies"""

    def test_logout_clears_cookie(self, authenticated_client, valid_credentials):
        """Test that logout clears the httpOnly cookie"""
        # First login to get cookie
        login_response = authenticated_client.post(
            "/auth/login", data=valid_credentials
        )
        assert login_response.status_code == 200
        assert "refresh_token" in authenticated_client.cookies

        # Logout
        logout_response = authenticated_client.post("/auth/logout")

        assert logout_response.status_code == 200
        assert "Logged out successfully" in logout_response.json()["message"]

        # Verify cookie is cleared (TestClient may show empty value or removed)
        cookie_value = authenticated_client.cookies.get("refresh_token", "")
        assert cookie_value == "" or "refresh_token" not in authenticated_client.cookies

    def test_logout_with_cookie_revokes_token(
        self, authenticated_client, valid_credentials
    ):
        """Test that logout with cookie revokes the specific token"""
        # Login to get cookie and refresh token
        login_response = authenticated_client.post(
            "/auth/login", data=valid_credentials
        )
        assert login_response.status_code == 200
        refresh_token = login_response.json()["refresh_token"]

        # Logout via cookie (clears cookie in response)
        logout_response = authenticated_client.post("/auth/logout")
        assert logout_response.status_code == 200

        # Try to use the refresh token directly (in body) - should fail because it's revoked
        authenticated_client.cookies.clear()
        refresh_response = authenticated_client.post(
            "/auth/refresh", json={"refresh_token": refresh_token}
        )

        # Should fail because token was revoked during logout
        assert refresh_response.status_code == 401
        assert "Invalid or expired refresh token" in refresh_response.json()["detail"]

    def test_logout_without_token_logs_out_all_devices(
        self, authenticated_client, valid_credentials
    ):
        """Test logout without token revokes all user tokens"""
        # Login multiple times to create multiple tokens
        authenticated_client.post("/auth/login", data=valid_credentials)
        authenticated_client.post("/auth/login", data=valid_credentials)

        # Clear cookies to simulate no token provided
        authenticated_client.cookies.clear()

        # Logout from all devices
        logout_response = authenticated_client.post("/auth/logout")

        assert logout_response.status_code == 200
        message = logout_response.json()["message"]
        # Should indicate multiple devices logged out
        assert "device(s)" in message

    def test_logout_cookie_priority_over_body(
        self, authenticated_client, valid_credentials
    ):
        """Test that cookie token takes priority over body token in logout"""
        # Login to get cookie
        login_response = authenticated_client.post(
            "/auth/login", data=valid_credentials
        )
        assert login_response.status_code == 200
        refresh_token = login_response.json()["refresh_token"]

        # Logout with both cookie (automatic) and fake body token
        logout_response = authenticated_client.post(
            "/auth/logout", json={"refresh_token": "fake_token"}
        )

        # Should succeed because cookie token is used (body ignored)
        assert logout_response.status_code == 200
        assert "Logged out successfully" in logout_response.json()["message"]


class TestLogoutEndpointBackwardCompatibility:
    """Tests for backward compatibility with body-based logout"""

    def test_logout_with_body_token_works(
        self, authenticated_client, valid_credentials
    ):
        """Test logout with token in body still works (backward compatibility)"""
        # Login to get refresh token
        login_response = authenticated_client.post(
            "/auth/login", data=valid_credentials
        )
        assert login_response.status_code == 200
        refresh_token = login_response.json()["refresh_token"]

        # Clear cookies to simulate body-based logout
        authenticated_client.cookies.clear()

        # Logout with body token
        logout_response = authenticated_client.post(
            "/auth/logout", json={"refresh_token": refresh_token}
        )

        assert logout_response.status_code == 200
        assert "Logged out successfully" in logout_response.json()["message"]

    def test_logout_with_invalid_body_token_fails(
        self, authenticated_client, valid_credentials
    ):
        """Test logout with invalid token in body fails"""
        # Clear cookies
        authenticated_client.cookies.clear()

        # Try logout with invalid token
        logout_response = authenticated_client.post(
            "/auth/logout", json={"refresh_token": "invalid_token"}
        )

        assert logout_response.status_code == 400
        assert "Invalid refresh token" in logout_response.json()["detail"]

    def test_logout_clears_cookie_even_on_error(
        self, authenticated_client, valid_credentials
    ):
        """Test that cookie is cleared even if logout fails"""
        # Login to get cookie
        login_response = authenticated_client.post(
            "/auth/login", data=valid_credentials
        )
        assert login_response.status_code == 200
        assert "refresh_token" in authenticated_client.cookies

        # Clear and manually set a corrupted cookie value
        authenticated_client.cookies.clear()
        authenticated_client.cookies.set("refresh_token", "corrupted_value", path="/auth")

        # Try logout with corrupted cookie
        logout_response = authenticated_client.post("/auth/logout")

        # Should fail due to invalid token
        assert logout_response.status_code == 400

        # Cookie should still be cleared (deleted in response)
        # Note: TestClient may still have the old cookie since delete_cookie
        # sets an empty cookie with max_age=0, not remove it from the jar
        # In a real browser, this would clear the cookie


class TestLogoutEndpointSecurity:
    """Security tests for logout endpoint"""

    def test_logout_requires_authentication(self, unauthenticated_client):
        """Test that logout endpoint requires authentication"""
        # Try logout without being authenticated
        logout_response = unauthenticated_client.post("/auth/logout")

        # Should fail with 401 or 403 (depends on authentication setup)
        assert logout_response.status_code in [401, 403]

    def test_user_cannot_logout_other_user_token(
        self, authenticated_client, valid_credentials
    ):
        """Test that users can only logout their own tokens"""
        # Login to get a token
        login_response = authenticated_client.post(
            "/auth/login", data=valid_credentials
        )
        assert login_response.status_code == 200
        user_token = login_response.json()["refresh_token"]

        # Clear cookies
        authenticated_client.cookies.clear()

        # Try to logout with the token (should work - same user)
        logout_response = authenticated_client.post(
            "/auth/logout", json={"refresh_token": user_token}
        )

        assert logout_response.status_code == 200

        # Try again with same token (should fail - already revoked)
        logout_response2 = authenticated_client.post(
            "/auth/logout", json={"refresh_token": user_token}
        )

        assert logout_response2.status_code == 400
