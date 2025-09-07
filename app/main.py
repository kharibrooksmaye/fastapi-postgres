from typing import Union
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Book(BaseModel):
    title: str
    author: str
    year: int
    call_number: float
    is_checked_out: bool
@app.get("/")
async def read_root():
    return {"Hello": "World"}

@app.get("/book/{book_id}")
async def get_book(book_id: int, q: Union[str, None] = None):
    return {"book_id": book_id, "q": q}

@app.post("/book/")
async def create_book(book: Book):
    return {"message": f"Book '{book.title}' by {book.author} created successfully."}

@app.put("/book/{book_id}")
async def update_book(book_id: int, book: Book):
    return {"book_title": book.title, "book_id": book_id}