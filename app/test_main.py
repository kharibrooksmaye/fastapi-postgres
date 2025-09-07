from fastapi.testclient import TestClient
from .main import app, Book

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}

def test_get_book():
    response = client.get("/book/1")
    assert response.status_code == 200
    assert response.json() == {"book_id": 1, "q": None}

def test_create_book():
    new_book = Book(title="1984", author="George Orwell", year=1949, call_number=123.456, is_checked_out=False)
    response = client.post("/book/", json=new_book.model_dump())
    assert response.status_code == 200
    assert response.json() == {"message": "Book '1984' by George Orwell created successfully."}

def test_update_book():
    updated_book = Book(title="Animal Farm", author="George Orwell", year=1945, call_number=123.456, is_checked_out=False)
    response = client.put("/book/1", json=updated_book.model_dump())
    assert response.status_code == 200
    assert response.json() == {"book_title": "Animal Farm", "book_id": 1}