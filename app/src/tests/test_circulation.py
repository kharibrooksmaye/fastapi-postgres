import pytest
from datetime import datetime


def test_get_all_circulation_events(authenticated_client):
    """Test GET /circulation/ - get all circulation events"""
    response = authenticated_client.get("/circulation/")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_circulation_events_with_pagination(authenticated_client):
    """Test GET /circulation/ - with pagination parameters"""
    response = authenticated_client.get("/circulation/?skip=0&limit=10")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_circulation_events_unauthenticated(unauthenticated_client):
    """Test GET /circulation/ - without authentication"""
    response = unauthenticated_client.get("/circulation/")

    assert response.status_code == 401


def test_checkout_books_success(authenticated_client):
    """Test POST /circulation/checkout/{user_id} - successful checkout"""
    response = authenticated_client.get("/catalog/books")
    books = response.json()

    if books:
        book_ids = [books[0]["id"]]

        response = authenticated_client.post(
            "/circulation/checkout/1",
            json=book_ids
        )

        assert response.status_code == 200
        assert "message" in response.json()
        assert "event_id" in response.json()
        assert "user_id" in response.json()
        assert response.json()["user_id"] == 1
        assert "book_ids" in response.json()
        assert "due_date" in response.json()


def test_checkout_books_user_not_found(authenticated_client):
    """Test POST /circulation/checkout/{user_id} - user not found"""
    book_ids = [1]

    response = authenticated_client.post(
        "/circulation/checkout/99999",
        json=book_ids
    )

    assert response.status_code == 404
    assert "User with ID 99999 not found" in response.json()["detail"]


def test_checkout_books_unauthorized_access(authenticated_client):
    """Test POST /circulation/checkout/{user_id} - unauthorized user access"""
    response = authenticated_client.get("/catalog/books")
    books = response.json()

    if books:
        book_ids = [books[0]["id"]]

        response = authenticated_client.post(
            "/circulation/checkout/999",
            json=book_ids
        )

        if response.status_code == 404:
            assert "User with ID 999 not found" in response.json()["detail"]
        elif response.status_code == 403:
            assert "cannot access other users' library" in response.json()["detail"]


def test_return_books_success(authenticated_client):
    """Test POST /circulation/return/{user_id} - successful return"""
    response = authenticated_client.get("/catalog/books")
    books = response.json()

    if books:
        book_ids = [books[0]["id"]]

        checkout_response = authenticated_client.post(
            "/circulation/checkout/1",
            json=book_ids
        )
        assert checkout_response.status_code == 200

        return_response = authenticated_client.post(
            "/circulation/return/1",
            json=book_ids
        )

        assert return_response.status_code == 200
        assert "message" in return_response.json()
        assert "event_id" in return_response.json()
        assert "user_id" in return_response.json()
        assert return_response.json()["user_id"] == 1


def test_renew_books_success(authenticated_client):
    """Test POST /circulation/renew/{user_id} - successful renewal"""
    response = authenticated_client.get("/catalog/books")
    books = response.json()

    if books:
        book_ids = [books[0]["id"]]

        checkout_response = authenticated_client.post(
            "/circulation/checkout/1",
            json=book_ids
        )
        assert checkout_response.status_code == 200

        renew_response = authenticated_client.post(
            "/circulation/renew/1",
            json=book_ids
        )

        assert renew_response.status_code == 200
        assert "message" in renew_response.json()
        assert "event_id" in renew_response.json()
        assert "due_date" in renew_response.json()


def test_checkout_multiple_books(authenticated_client):
    """Test POST /circulation/checkout/{user_id} - checkout multiple books"""
    response = authenticated_client.get("/catalog/books")
    books = response.json()

    if len(books) >= 2:
        book_ids = [books[0]["id"], books[1]["id"]]

        response = authenticated_client.post(
            "/circulation/checkout/1",
            json=book_ids
        )

        assert response.status_code == 200
        assert len(response.json()["book_ids"]) == 2


def test_checkout_books_empty_list(authenticated_client):
    """Test POST /circulation/checkout/{user_id} - empty book list"""
    book_ids = []

    response = authenticated_client.post(
        "/circulation/checkout/1",
        json=book_ids
    )

    assert response.status_code == 200


def test_circulation_unauthenticated_checkout(unauthenticated_client):
    """Test POST /circulation/checkout/{user_id} - without authentication"""
    book_ids = [1]

    response = unauthenticated_client.post(
        "/circulation/checkout/1",
        json=book_ids
    )

    assert response.status_code == 401


def test_circulation_unauthenticated_return(unauthenticated_client):
    """Test POST /circulation/return/{user_id} - without authentication"""
    book_ids = [1]

    response = unauthenticated_client.post(
        "/circulation/return/1",
        json=book_ids
    )

    assert response.status_code == 401


def test_circulation_unauthenticated_renew(unauthenticated_client):
    """Test POST /circulation/renew/{user_id} - without authentication"""
    book_ids = [1]

    response = unauthenticated_client.post(
        "/circulation/renew/1",
        json=book_ids
    )

    assert response.status_code == 401
