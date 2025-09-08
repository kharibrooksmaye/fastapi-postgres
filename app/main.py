from typing import Union
from fastapi import FastAPI
from pydantic import BaseModel

from app.mocks.mock_data import mock_books, mock_patrons


app = FastAPI()

class Book(BaseModel):
    title: str
    author: str
    published_year: int
    call_number: float
    genre: Union[str, None] = None
    summary: Union[str, None] = None
    is_checked_out: bool
@app.get("/")
async def read_root():
    return {"Hello": "World"}

# Book endpoints

@app.get("/books/")
async def get_books():
    return {"books": mock_books}

@app.get("/books/{book_id}")
async def get_book(book_id: int, q: Union[str, None] = None):
    book = next((book for book in mock_books if book["id"] == book_id), None)
    return {"book": book, "q": q}

@app.post("/books/")
async def create_book(book: Book):
    book_dict = book.model_dump()
    last_name = book.author.split(" ")[1]
    complete_call_number = f"{book.call_number} {last_name}"
    book_dict.update({"complete_call_number": complete_call_number})
    return book_dict

@app.put("/books/{book_id}")
async def update_book(book_id: int, book: Book):
    return {"book_title": book.title, "book_id": book_id}

@app.delete("/books/{book_id}")
async def delete_book(book_id: int):
    return {"book_id": book_id, "status": "deleted"}


# Patron endpoints
class Patron(BaseModel):
    name: str
    email: str
    member_id: int
    phone_number: Union[str, None] = None
    address: Union[str, None] = None
    is_active: Union[bool, None] = None
    
@app.get("/patrons/")
async def get_patrons():
    return {"patrons": mock_patrons}

@app.get("/patrons/me/")
async def get_my_info():
    return {"patron": mock_patrons[0]}  # Just an example, replace with actual user info

@app.get("/patrons/{patron_id}")
async def get_patron(patron_id: int):
    patron = next((p for p in mock_patrons if p["member_id"] == patron_id), None)
    return {"patron": patron}

@app.post("/patrons/")
async def create_patron(patron: Patron):
    patron_dict = patron.model_dump()
    message = f"Patron '{patron.name}' with member ID {patron.member_id} created successfully."
    return {"message": message, "patron": patron_dict}


# Administrative endpoints (checkout, return, fines)

@app.post("/patrons/{patron_id}/checkout/")
async def checkout_book(patron_id: int, book_ids: list[int]):
    return {"patron_id": patron_id, "book_ids": book_ids, "status": "checked out"}

@app.post("/patrons/{patron_id}/return/")
async def return_book(patron_id: int, book_ids: list[int]):
    return {"patron_id": patron_id, "book_ids": book_ids, "status": "returned"}

