import datetime
from typing import List
from sqlalchemy import TIMESTAMP, Column, true, ARRAY, Integer
from sqlmodel import Field, SQLModel

from app.src.schema.circulation import CatalogActionsEnum


class CatalogEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    action: CatalogActionsEnum = Field(default=None, nullable=False)
    event_timestamp: datetime.datetime = Field(
        sa_column=Column(TIMESTAMP(timezone=true), nullable=False)
    )
    user: int = Field(default=None, foreign_key="user.id")
    catalog_ids: List[int] = Field(
        sa_column=Column(ARRAY(Integer), nullable=True)
    )
    admin_id: int = Field(foreign_key="user.id")
    due_date: datetime.date = Field(
        sa_column=Column(TIMESTAMP(timezone=true), nullable=False)
    )
