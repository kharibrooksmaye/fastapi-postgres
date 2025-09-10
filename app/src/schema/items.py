from typing import Union
from pydantic import BaseModel

class Book(BaseModel):
    id: int 
    type: str = "book"
    title: str
    author: str
    published_year: int
    call_number: float
    genre: Union[str, None] = None
    summary: Union[str, None] = None
    is_checked_out: bool