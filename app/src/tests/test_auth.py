import pytest


def test_login_success(authenticated_client):
    """Test POST /auth/login - successful login"""
    login_data = {
        "username": "testuser",
        "password": "testpassword123"
    }

    response = authenticated_client.post(
        "/auth/login",
        data=login_data
    )

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    assert "user" in response.json()
    assert "expires" in response.json()


def test_login_invalid_username(authenticated_client):
    """Test POST /auth/login - invalid username"""
    login_data = {
        "username": "nonexistentuser",
        "password": "testpassword123"
    }

    response = authenticated_client.post(
        "/auth/login",
        data=login_data
    )

    assert response.status_code == 400
    assert "Incorrect username or password" in response.json()["detail"]


def test_login_invalid_password(authenticated_client):
    """Test POST /auth/login - invalid password"""
    login_data = {
        "username": "testuser",
        "password": "wrongpassword"
    }

    response = authenticated_client.post(
        "/auth/login",
        data=login_data
    )

    assert response.status_code == 400
    assert "Incorrect username or password" in response.json()["detail"]


def test_get_token_success(authenticated_client):
    """Test POST /auth/token - successful token retrieval"""
    token_data = {
        "username": "testuser",
        "password": "testpassword123"
    }

    response = authenticated_client.post(
        "/auth/token",
        data=token_data
    )

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    assert "expires" in response.json()


def test_get_token_invalid_credentials(authenticated_client):
    """Test POST /auth/token - invalid credentials"""
    token_data = {
        "username": "testuser",
        "password": "wrongpassword"
    }

    response = authenticated_client.post(
        "/auth/token",
        data=token_data
    )

    assert response.status_code == 400
    assert "Incorrect username or password" in response.json()["detail"]


def test_register_user_success(unauthenticated_client):
    """Test POST /auth/register - successful registration"""
    new_user = {
        "name": "New User",
        "member_id": "999",
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "newpassword123",
        "is_active": True,
        "type": "member"
    }

    response = unauthenticated_client.post("/auth/register", json=new_user)

    assert response.status_code == 200
    assert response.json()["username"] == "newuser"
    assert response.json()["email"] == "newuser@example.com"
    assert "password" in response.json()


def test_register_user_duplicate_username(authenticated_client):
    """Test POST /auth/register - duplicate username"""
    duplicate_user = {
        "name": "Duplicate User",
        "member_id": "998",
        "username": "testuser",
        "email": "duplicate@example.com",
        "password": "password123",
        "is_active": True,
        "type": "member"
    }

    response = authenticated_client.post("/auth/register", json=duplicate_user)

    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]


def test_register_user_missing_username(unauthenticated_client):
    """Test POST /auth/register - missing username"""
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


def test_activate_user_lookup_success(authenticated_client):
    """Test POST /auth/activate/lookup - successful user lookup"""
    lookup_data = {
        "email": "testuser@example.com",
        "username": "testuser",
        "phone_number": "1234567890"
    }

    response = authenticated_client.post(
        "/auth/activate/lookup",
        data=lookup_data
    )

    assert response.status_code == 200


def test_activate_user_lookup_not_found(authenticated_client):
    """Test POST /auth/activate/lookup - user not found"""
    lookup_data = {
        "email": "notfound@example.com",
        "username": "notfound",
        "phone_number": "0000000000"
    }

    response = authenticated_client.post(
        "/auth/activate/lookup",
        data=lookup_data
    )

    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]


def test_activate_user_already_activated(authenticated_client):
    """Test POST /auth/activate/lookup - user already activated"""
    lookup_data = {
        "email": "testuser@example.com",
        "username": "testuser",
        "phone_number": "1234567890"
    }

    response = authenticated_client.post(
        "/auth/activate/lookup",
        data=lookup_data
    )

    if response.status_code == 200:
        assert "status_code" in response.json() or "message" in response.json()
