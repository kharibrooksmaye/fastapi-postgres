from unittest.mock import AsyncMock
from fastapi.testclient import TestClient
from app.core.authentication import get_current_user, oauth2_scheme
from app.core.authorization import require_roles
from app.core.database import SessionDep
from app.main import app
from app.src.schema.users import User, UserTypeEnum

async def override_get_session():
    mock_session = AsyncMock()

    # Mock the exec method to return test data
    mock_result = AsyncMock()
    mock_result.first.return_value = User(
        id=1,
        name="Test User",
        member_id=1,
        username="testuser",
        email="testuser@example.com",
        password="$2b$12$KIXQJ4s0G7y8o9n5m1e5euFhFf8e8ZyFZyFZyFZyFZyFZyFZyFZy",
        is_active=True,
        type=UserTypeEnum.admin
    )
    mock_result.all.return_value = [mock_result.first.return_value]

    mock_session.exec.return_value = mock_result
    mock_session.add = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.delete = AsyncMock()

    yield mock_session

def override_get_my_info(session=None):
    """Mock function to override get_current_user dependency with optional session parameter"""
    hashed_password = "$2b$12$KIXQJ4s0G7y8o9n5m1e5euFhFf8e8ZyFZyFZyFZyFZyFZyFZyFZy"
    return User(
        name="Test User",
        member_id=1,
        username="testuser",
        email="testuser@example.com",
        password=hashed_password,
        is_active=True,
        type=UserTypeEnum.admin
    )

def override_oauth2_scheme():
    return "testtoken"
app.dependency_overrides[get_current_user] = override_get_my_info
app.dependency_overrides[oauth2_scheme] = override_oauth2_scheme
app.dependency_overrides[SessionDep] = override_get_session

client = TestClient(app)

# def test_get_my_info():
#     response = client.get("/users/me")
#     # Unauthenticated request should return 401
#     assert response.status_code == 200
#     assert "username" not in response.json()
    
# def test_get_single_user():
#     response = client.get("/users/1")
#     # Unauthenticated request should return 401
#     assert response.status_code == 401
#     assert "user" not in response.json()
    
# def test_get_all_users():
#     response = client.get("/users/")
#     # Unauthenticated request should return 401
#     assert response.status_code == 401
#     assert "users" not in response.json()
    
# def test_delete_user():
#     response = client.delete("/users/1")
#     # Unauthenticated request should return 403
#     assert response.status_code == 403
#     assert "detail" in response.json()
    
# def test_create_user():
#     response = client.post("/users/", json={
#         "username": "newuser",
#         "email": "newuser@example.com",
#         "password": "newpassword"
#     })
#     # Unauthenticated request should return 403
#     assert response.status_code == 403
#     assert "user" not in response.json()

def test_authenticated_requests():
    # Override get_current_user to simulate authenticated user
    app.dependency_overrides[get_current_user] = override_get_my_info
    
    response = client.get("/users/me/")
    print("Response status:", response.status_code)
    print("Response body:", response.json())
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
    
    response = client.get("/users/1")
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "testuser"
    
    response = client.get("/users/")
    assert response.status_code == 200
    assert isinstance(response.json()["users"], list)
    
    response = client.delete("/users/1")
    assert response.status_code == 200
    assert "detail" in response.json()
    
    response = client.post("/users/", json={
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "newpassword"
    })
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "newuser"