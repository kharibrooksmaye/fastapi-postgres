from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel


class RefreshToken(SQLModel, table=True):
    """
    Refresh token model for persistent login functionality.
    Stores long-lived tokens that can be used to obtain new access tokens.
    """

    __tablename__ = "refresh_tokens"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    token_hash: str = Field(index=True, unique=True)
    device_name: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    user_agent: Optional[str] = Field(default=None, max_length=512)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: datetime = Field(nullable=False)
    last_used_at: Optional[datetime] = Field(default=None)
    is_revoked: bool = Field(default=False, index=True)
    revoked_at: Optional[datetime] = Field(default=None)
