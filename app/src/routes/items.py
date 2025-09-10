from typing import Union
from fastapi import APIRouter, HTTPException

import app
from app.mocks.mock_data import mock_books
from app.src.models.items import Book
from app.core.database import SessionDep

router = APIRouter()

@router.get("/books/")
async def get_books():
    return {"books": mock_books}

@router.get("/books/{book_id}")
async def get_book(book_id: int, q: Union[str, None] = None):
    book = next((book for book in mock_books if book["id"] == book_id), None)
    return {"book": book, "q": q}

@router.post("/books/")
async def create_book(book: Book, session: SessionDep) -> Book:
    book_dict = book.model_dump()
    last_name = book.author.split(" ")[1]
    complete_call_number = f"{book.call_number} {last_name}"
    book_dict.update({"complete_call_number": complete_call_number})
    
    session.add(book)
    await session.commit()
    await session.refresh(book)
    return book

@router.put("/books/{book_id}")
async def update_book(book_id: int, book: Book, session: SessionDep):
    db_book = await session.get(Book, book_id)
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    book_dict = book.model_dump()
    last_name = book.author.split(" ")[1]
    complete_call_number = f"{book.call_number} {last_name}"
    book_dict.update({"complete_call_number": complete_call_number})
    for key, value in book_dict.items():
        setattr(db_book, key, value)
    await session.commit()
    await session.refresh(db_book)
    return db_book

@router.delete("/books/{book_id}")
async def delete_book(book_id: int, session: SessionDep):
    db_book = await session.get(Book, book_id)
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    await session.delete(db_book)
    await session.commit()
    return {"book_id": book_id, "status": "deleted"}
