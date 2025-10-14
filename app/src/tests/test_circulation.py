import pytest


@pytest.fixture
def get_book_ids(authenticated_client):
    """Helper fixture to get book IDs from catalog"""
    def _get_books(count=1):
        response = authenticated_client.get("/catalog/books")
        books = response.json()
        if books and len(books) >= count:
            return [books[i]["id"] for i in range(count)]
        return []
    return _get_books


@pytest.fixture
def circulation_helper(authenticated_client):
    """Helper fixture for common circulation operations"""
    def _perform_action(action, user_id, book_ids):
        return authenticated_client.post(
            f"/circulation/{action}/{user_id}",
            json=book_ids
        )
    return _perform_action


@pytest.mark.parametrize("endpoint,params", [
    ("/circulation/", ""),
    ("/circulation/", "?skip=0&limit=10"),
])
def test_get_circulation_events(authenticated_client, endpoint, params):
    """Test GET circulation events with various parameters"""
    response = authenticated_client.get(f"{endpoint}{params}")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_circulation_events_unauthenticated(unauthenticated_client):
    """Test GET circulation events without authentication"""
    response = unauthenticated_client.get("/circulation/")
    assert response.status_code == 401


def test_checkout_books_success(circulation_helper, get_book_ids):
    """Test successful book checkout"""
    book_ids = get_book_ids(1)

    if book_ids:
        response = circulation_helper("checkout", 1, book_ids)

        assert response.status_code == 200
        assert "message" in response.json()
        assert "event_id" in response.json()
        assert response.json()["user_id"] == 1
        assert "book_ids" in response.json()
        assert "due_date" in response.json()


@pytest.mark.parametrize("user_id,expected_status,expected_message", [
    (99999, 404, "User with ID 99999 not found"),
])
def test_checkout_books_errors(authenticated_client, user_id, expected_status, expected_message):
    """Test checkout with various error scenarios"""
    book_ids = [1]
    response = authenticated_client.post(f"/circulation/checkout/{user_id}", json=book_ids)

    assert response.status_code == expected_status
    assert expected_message in response.json()["detail"]


def test_checkout_books_unauthorized_access(circulation_helper, get_book_ids):
    """Test checkout with unauthorized user access"""
    book_ids = get_book_ids(1)

    if book_ids:
        response = circulation_helper("checkout", 999, book_ids)

        assert response.status_code in [403, 404]
        if response.status_code == 404:
            assert "User with ID 999 not found" in response.json()["detail"]
        elif response.status_code == 403:
            assert "cannot access other users' library" in response.json()["detail"]


@pytest.mark.parametrize("action,expected_fields", [
    ("return", ["message", "event_id", "user_id"]),
    ("renew", ["message", "event_id", "due_date"]),
])
def test_circulation_actions_success(circulation_helper, get_book_ids, action, expected_fields):
    """Test return and renew actions"""
    book_ids = get_book_ids(1)

    if book_ids:
        checkout_response = circulation_helper("checkout", 1, book_ids)
        assert checkout_response.status_code == 200

        action_response = circulation_helper(action, 1, book_ids)

        assert action_response.status_code == 200
        for field in expected_fields:
            assert field in action_response.json()


def test_checkout_multiple_books(circulation_helper, get_book_ids):
    """Test checkout with multiple books"""
    book_ids = get_book_ids(2)

    if len(book_ids) >= 2:
        response = circulation_helper("checkout", 1, book_ids)

        assert response.status_code == 200
        assert len(response.json()["book_ids"]) == 2


def test_checkout_books_empty_list(circulation_helper):
    """Test checkout with empty book list"""
    response = circulation_helper("checkout", 1, [])
    assert response.status_code == 200


@pytest.mark.parametrize("action", ["checkout", "return", "renew"])
def test_circulation_unauthenticated(unauthenticated_client, action):
    """Test circulation actions without authentication"""
    book_ids = [1]
    response = unauthenticated_client.post(f"/circulation/{action}/1", json=book_ids)
    assert response.status_code == 401
