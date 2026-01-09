def test_authenticated_requests(authenticated_client):
    response = authenticated_client.get("/users/me/")
    print("Response status:", response.status_code)
    print("Response body:", response.json())
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
    
    response = authenticated_client.get("/users/1")
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "testuser"
    
    response = authenticated_client.get("/users/")
    assert response.status_code == 200
    assert isinstance(response.json()["users"], list)
    
    # Create a new user first (so we can delete it without FK issues)
    response = authenticated_client.post("/users/", json={
        "name": "Deletable User",
        "username": "deletableuser",
        "email": "deletable@example.com",
        "password": "Xk9$mPq2!wLz"
    })
    assert response.status_code == 200
    new_user_id = response.json()["user"]["id"]
    
    # Now delete the newly created user (no FK constraints)
    response = authenticated_client.delete(f"/users/{new_user_id}")
    assert response.status_code == 200
    assert "message" in response.json()
    
    # Create another user for the general create test
    response = authenticated_client.post("/users/", json={
        "name": "Test User",
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "Xk9$mPq2!wLz"
    })
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "newuser"
    
def test_get_my_info(unauthenticated_client):
    response = unauthenticated_client.get("/users/me")
    assert response.status_code == 401
    assert "username" not in response.json()
    
def test_get_single_user(unauthenticated_client):
    response = unauthenticated_client.get("/users/1")
    assert response.status_code == 401
    assert "user" not in response.json()
    
def test_get_all_users(unauthenticated_client):
    response = unauthenticated_client.get("/users/")
    assert response.status_code == 401
    assert "users" not in response.json()
    
def test_delete_user(unauthenticated_client):
    response = unauthenticated_client.delete("/users/1")
    assert response.status_code == 401
    assert "detail" in response.json()
    
def test_create_user(unauthenticated_client):
    response = unauthenticated_client.post("/users/", json={
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "newpassword"
    })
    assert response.status_code == 401
    assert "user" not in response.json()
