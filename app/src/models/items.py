from sqlalchemy import table
from sqlmodel import Field, SQLModel


class Book(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    type: str = Field(default="book", index=True)
    title: str = Field(index=True)
    author: str = Field(index=True)
    published_year: int = Field(index=True)
    call_number: float = Field(index=True)
    genre: str = Field(default=None, index=True)
    summary: str = Field(default=None, index=True)
    is_checked_out: bool = Field(default=False)