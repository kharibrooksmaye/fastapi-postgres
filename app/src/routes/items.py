from typing import Union
from fastapi import APIRouter

import app
from app.mocks.mock_data import mock_books
from app.src.schema.items import Book

router = APIRouter()

@router.get("/books/")
async def get_books():
    return {"books": mock_books}

@router.get("/books/{book_id}")
async def get_book(book_id: int, q: Union[str, None] = None):
    book = next((book for book in mock_books if book["id"] == book_id), None)
    return {"book": book, "q": q}

@router.post("/books/")
async def create_book(book: Book):
    book_dict = book.model_dump()
    last_name = book.author.split(" ")[1]
    complete_call_number = f"{book.call_number} {last_name}"
    book_dict.update({"complete_call_number": complete_call_number})
    return book_dict

@router.put("/books/{book_id}")
async def update_book(book_id: int, book: Book):
    return {"book_title": book.title, "book_id": book_id}

@router.delete("/books/{book_id}")
async def delete_book(book_id: int):
    return {"book_id": book_id, "status": "deleted"}
