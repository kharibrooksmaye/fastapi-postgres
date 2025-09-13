from enum import Enum
from typing import Union
from pydantic import BaseModel


class ItemTypeEnum(str, Enum):
    book = "book"
    magazine = "magazine"
    dvd = "dvd"
    bluray = "bluray"
    cd = "cd"
    newspaper = "newspaper"


class Item(BaseModel):
    id: int
    type: ItemTypeEnum
    title: str
    call_number: float
    genre: Union[str, None] = None
    summary: Union[str, None] = None
    is_checked_out: bool


class Book(Item):
    type: ItemTypeEnum = ItemTypeEnum.book
    author: str
    published_year: int


class PrintMedia(Item):
    type: ItemTypeEnum = ItemTypeEnum.magazine | ItemTypeEnum.newspaper
    publisher: str
    first_issue_year: int


class VideoMedia(Item):
    type: ItemTypeEnum = ItemTypeEnum.dvd | ItemTypeEnum.bluray
    director: str
    released_year: int


class AudioMedia(Item):
    type: ItemTypeEnum = ItemTypeEnum.cd
    artist: str
    released_year: int
