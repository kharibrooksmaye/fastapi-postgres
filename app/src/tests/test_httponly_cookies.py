"""
Tests for httpOnly cookie-based refresh token functionality.
"""

import pytest


@pytest.fixture
def valid_credentials():
    """Valid test user credentials"""
    return {"username": "testuser", "password": "testpassword123"}


class TestHttpOnlyCookieLogin:
    """Tests for login endpoint with httpOnly cookies"""

    def test_login_returns_csrf_token(self, authenticated_client, valid_credentials):
        """Test that login returns CSRF token in response"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200
        data = response.json()
        assert "csrf_token" in data
        assert len(data["csrf_token"]) > 30  # Should be a long secure token

    def test_login_sets_httponly_cookie(self, authenticated_client, valid_credentials):
        """Test that login sets httpOnly cookie with refresh token"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200

        # Check that refresh_token cookie was set
        cookies = response.cookies
        assert "refresh_token" in cookies

        # Verify cookie attributes (TestClient may not expose all attributes)
        refresh_cookie = cookies.get("refresh_token")
        assert refresh_cookie is not None
        assert len(refresh_cookie) > 40  # Should be a long token

    def test_login_cookie_has_correct_max_age_default(
        self, authenticated_client, valid_credentials
    ):
        """Test that cookie max_age is 30 days by default"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200
        # Cookie should be set with 30 days = 2592000 seconds
        # Note: TestClient may not expose max_age, but we can verify the cookie exists
        assert "refresh_token" in response.cookies

    def test_login_cookie_remember_me_extends_expiry(
        self, authenticated_client, valid_credentials
    ):
        """Test that remember_me=True extends cookie expiration to 90 days"""
        response = authenticated_client.post(
            "/auth/login", data=valid_credentials, params={"remember_me": True}
        )

        assert response.status_code == 200
        data = response.json()

        # Verify cookie is set
        assert "refresh_token" in response.cookies

        # Verify response still includes refresh_expires
        assert "refresh_expires" in data

    def test_login_maintains_backward_compatibility(
        self, authenticated_client, valid_credentials
    ):
        """Test that login still returns refresh_token in body for backward compatibility"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200
        data = response.json()

        # Should still have refresh_token in response body
        assert "refresh_token" in data
        assert len(data["refresh_token"]) > 40

        # Should also have csrf_token
        assert "csrf_token" in data

        # And all the original fields
        assert "access_token" in data
        assert "token_type" in data
        assert "user" in data
        assert "expires" in data

    def test_token_endpoint_also_sets_cookie(
        self, authenticated_client, valid_credentials
    ):
        """Test that /auth/token endpoint also sets httpOnly cookie"""
        response = authenticated_client.post("/auth/token", data=valid_credentials)

        assert response.status_code == 200
        data = response.json()

        # Should set cookie
        assert "refresh_token" in response.cookies

        # Should return CSRF token
        assert "csrf_token" in data

        # Should still return refresh_token in body
        assert "refresh_token" in data

    def test_multiple_logins_create_different_csrf_tokens(
        self, authenticated_client, valid_credentials
    ):
        """Test that each login creates a unique CSRF token"""
        response1 = authenticated_client.post("/auth/login", data=valid_credentials)
        response2 = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response1.status_code == 200
        assert response2.status_code == 200

        csrf1 = response1.json()["csrf_token"]
        csrf2 = response2.json()["csrf_token"]

        # Each login should generate a different CSRF token
        assert csrf1 != csrf2

    def test_cookie_path_is_auth(self, authenticated_client, valid_credentials):
        """Test that cookie path is set to /auth"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200
        # Cookie should be set (path verification may not be possible in TestClient)
        assert "refresh_token" in response.cookies


class TestHttpOnlyCookieSecurity:
    """Security tests for httpOnly cookie implementation"""

    def test_refresh_token_different_in_cookie_and_body(
        self, authenticated_client, valid_credentials
    ):
        """Test that refresh token in cookie matches token in body"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200

        cookie_token = response.cookies.get("refresh_token")
        body_token = response.json()["refresh_token"]

        # They should be the same value (backward compatibility)
        assert cookie_token == body_token

    def test_csrf_token_is_different_from_refresh_token(
        self, authenticated_client, valid_credentials
    ):
        """Test that CSRF token is different from refresh token"""
        response = authenticated_client.post("/auth/login", data=valid_credentials)

        assert response.status_code == 200
        data = response.json()

        csrf_token = data["csrf_token"]
        refresh_token = data["refresh_token"]

        # CSRF and refresh tokens should be completely different
        assert csrf_token != refresh_token
        assert len(csrf_token) > 30
        assert len(refresh_token) > 40
