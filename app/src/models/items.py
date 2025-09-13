from sqlmodel import Field, SQLModel


class Item(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    type: str = Field(default="book", index=True)
    title: str = Field(index=True)

    # Book-specific fields
    author: str | None = Field(default=None, index=True)
    published_year: int | None = Field(default=None, index=True)

    # Media-specific fields (for DVDs, CDs, etc.)
    director: str | None = Field(default=None, index=True)
    artist: str | None = Field(default=None, index=True)
    released_year: int | None = Field(default=None, index=True)

    # Magazine/Newspaper fields
    publisher: str | None = Field(default=None, index=True)
    first_issue_year: int | None = Field(default=None, index=True)

    # Common fields
    call_number: str | None = Field(default=None, index=True)
    genre: str | None = Field(default=None, index=True)
    summary: str | None = Field(default=None, index=True)
    is_checked_out: bool = Field(default=False)
