from typing import AsyncIterator
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlmodel import Field, Session, SQLModel, create_engine, select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine



from .settings import settings

postgres_url = f"postgresql+psycopg://{settings.db_user}:{settings.db_pw}@{settings.db_endpoint}:5432/{settings.db_name}"

engine = create_async_engine(postgres_url, echo=True)
    

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSession(engine) as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise e
        finally:
            await session.close()