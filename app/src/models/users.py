from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    type: str = Field(default="patron", index=True)
    name: str = Field(index=True)
    email: str = Field(index=True, unique=True)
    member_id: int = Field(index=True, unique=True)
    phone_number: str | None = None
    address: str | None = None
    is_active: bool = Field(default=False)
    username: str = Field(index=True)
    password: str
    
