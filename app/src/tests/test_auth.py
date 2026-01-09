import pytest


@pytest.fixture
def valid_credentials():
    """Valid test user credentials"""
    return {"username": "testuser", "password": "testpassword123"}


@pytest.fixture
def new_user_data():
    """Factory for creating new user data with secure password"""
    def _create_user(username="newuser", email="newuser@example.com", member_id="999"):
        return {
            "name": "Jane Smith",  # Name that won't conflict with password
            "member_id": member_id,
            "username": username,
            "email": email,
            "password": "Xk9$mPq2!wLz",  # Strong password: upper, lower, number, special, no patterns
            "is_active": True,
            "type": "member"
        }
    return _create_user


@pytest.mark.parametrize("endpoint", ["/auth/login", "/auth/token"])
def test_auth_success(authenticated_client, valid_credentials, endpoint):
    """Test successful authentication for login and token endpoints"""
    response = authenticated_client.post(endpoint, data=valid_credentials)

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    assert "expires" in response.json()
    if endpoint == "/auth/login":
        assert "user" in response.json()


@pytest.mark.parametrize("endpoint,username,password", [
    ("/auth/login", "nonexistentuser", "testpassword123"),
    ("/auth/login", "testuser", "wrongpassword"),
    ("/auth/token", "testuser", "wrongpassword"),
])
def test_auth_invalid_credentials(authenticated_client, endpoint, username, password):
    """Test authentication with invalid credentials"""
    response = authenticated_client.post(
        endpoint,
        data={"username": username, "password": password}
    )

    assert response.status_code == 400
    assert "Incorrect username or password" in response.json()["detail"]


def test_register_user_success(unauthenticated_client, new_user_data):
    """Test successful user registration"""
    user_data = new_user_data()
    response = unauthenticated_client.post("/auth/register", json=user_data)

    assert response.status_code == 200
    assert response.json()["username"] == user_data["username"]
    assert response.json()["email"] == user_data["email"]
    assert "password" in response.json()


def test_register_user_duplicate_username(authenticated_client, new_user_data):
    """Test registration with duplicate username"""
    user_data = new_user_data(username="testuser", email="duplicate@example.com", member_id="998")
    response = authenticated_client.post("/auth/register", json=user_data)

    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]


def test_register_user_missing_username(unauthenticated_client):
    """Test registration with missing username"""
    invalid_user = {
        "name": "Invalid User",
        "member_id": "997",
        "email": "invalid@example.com",
        "password": "password123",
        "is_active": True,
        "type": "member"
    }

    response = unauthenticated_client.post("/auth/register", json=invalid_user)

    assert response.status_code == 400
    assert "Username and password are required" in response.json()["detail"]


@pytest.mark.parametrize("email,username,phone,expected_status", [
    ("testuser@example.com", "testuser", "1234567890", 200),
    ("notfound@example.com", "notfound", "0000000000", 404),
])
def test_activate_user_lookup(authenticated_client, email, username, phone, expected_status):
    """Test user activation lookup with various scenarios"""
    lookup_data = {
        "email": email,
        "username": username,
        "phone_number": phone
    }

    response = authenticated_client.post("/auth/activate/lookup", data=lookup_data)

    assert response.status_code == expected_status
    if expected_status == 404:
        assert "User not found" in response.json()["detail"]
    elif expected_status == 200:
        assert "status_code" in response.json() or "message" in response.json()
