from contextlib import asynccontextmanager
from typing import Annotated
from fastapi import Depends
from sqlalchemy import AsyncAdaptedQueuePool
from sqlmodel import SQLModel, create_engine
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncEngine
from supabase import AsyncClient


from .settings import settings

postgres_url = f"postgresql+psycopg_async://{settings.db_user}:{settings.db_pw}@{settings.db_endpoint}:{settings.db_port}/{settings.db_name}?sslmode=require"

async_engine = AsyncEngine(
    create_engine(
        postgres_url,
        echo=False,
        future=True,
        poolclass=AsyncAdaptedQueuePool,
        pool_size=5,  # Reduced for Supabase compatibility
        max_overflow=5,  # Reduced for Supabase compatibility
        pool_pre_ping=True,
        pool_recycle=300,  # 5 minutes instead of 1 hour (better for Supabase pooler)
    )
)

async def get_supabase_client() -> AsyncClient:
    supabase = await AsyncClient.create(
        settings.supabase_url, settings.supabase_service_key
    )
    return supabase

async def init_db():
    async with async_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

async_session_maker = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)
@asynccontextmanager
async def session_context():
    async with async_session_maker() as session:
        yield session


async def get_session():
    async with async_session_maker() as session:
        yield session

SupabaseAsyncClientDep = Annotated[AsyncClient, Depends(get_supabase_client)]

SessionDep = Annotated[AsyncSession, Depends(get_session)]
