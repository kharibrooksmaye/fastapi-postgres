from fastapi.testclient import TestClient
from .main import app, Book
from app.mocks.mock_data import mock_users, mock_items

client = TestClient(app)


def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}


def test_get_books():
    response = client.get("/books/")
    assert response.status_code == 200
    assert response.json() == {"books": mock_items}


def test_get_book():
    response = client.get("/books/1")
    assert response.status_code == 200
    assert response.json() == {"book": mock_items[0], "q": None}


def test_create_book():
    new_book = Book(
        title="1984",
        author="George Orwell",
        published_year=1949,
        genre="Dystopian",
        summary="A dystopian novel",
        call_number=123.456,
        is_checked_out=False,
    )
    response = client.post("/books/", json=new_book.model_dump())
    assert response.status_code == 200
    assert response.json() == {
        "message": "Book '1984' by George Orwell created successfully."
    }


def test_update_book():
    updated_book = Book(
        title="Animal Farm",
        author="George Orwell",
        published_year=1945,
        genre="Dystopian",
        summary="A dystopian novel",
        call_number=123.456,
        is_checked_out=False,
    )
    response = client.put("/books/1", json=updated_book.model_dump())
    assert response.status_code == 200
    assert response.json() == {"book_title": "Animal Farm", "book_id": 1}


def test_get_patron():
    response = client.get("/patrons/1")
    assert response.status_code == 200
    assert response.json() == {"patron": mock_users[0]}


def test_get_patrons():
    response = client.get("/patrons/")
    assert response.status_code == 200
    assert response.json() == {"patrons": mock_users}
