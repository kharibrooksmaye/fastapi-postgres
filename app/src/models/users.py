from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    type: str = Field(default="patron", index=True)
    name: str = Field(index=True)
    email: Optional[str] = Field(index=True, unique=True)
    member_id: Optional[str] = Field(index=True, unique=True)
    phone_number: Optional[str] = None
    address: Optional[str] = None
    is_active: bool = Field(default=False)
    username: str = Field(index=True)
    password: str
    activation_token_hash: Optional[str] = Field(default=None, index=True)
    activation_token_expires: Optional[datetime] = Field(default=None)
    activation_token_used: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)