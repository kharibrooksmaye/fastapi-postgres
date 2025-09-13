from contextlib import asynccontextmanager
from typing import Annotated
from fastapi import Depends
from sqlalchemy import NullPool
from sqlmodel import SQLModel, create_engine
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncEngine


from .settings import settings

postgres_url = f"postgresql+asyncpg://{settings.db_user}:{settings.db_pw}@{settings.db_endpoint}:5432/{settings.db_name}"

async_engine = AsyncEngine(
    create_engine(postgres_url, echo=True, future=True, poolclass=NullPool)
)


async def init_db():
    async with async_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


@asynccontextmanager
async def session_context():
    async_session = sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session


async def get_session():
    async_session = sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]
