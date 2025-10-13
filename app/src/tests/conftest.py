import pytest
from fastapi.testclient import TestClient
from pytest_postgresql import factories
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from app.core.authentication import get_current_user, oauth2_scheme
from app.core.database import get_session
from app.main import app
from app.src.tests.utils import TestDatabase, override_get_my_info, override_oauth2_scheme

postgresql_process = factories.postgresql_proc(
    executable="/opt/homebrew/opt/postgresql@16/bin/pg_ctl"
)
postgresql_session = factories.postgresql("postgresql_process")

client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def create_and_delete_database(postgresql_session):
    url = f"postgresql+psycopg://{postgresql_session.info.user}@{postgresql_session.info.host}:{postgresql_session.info.port}/{postgresql_session.info.dbname}"
    engine = create_engine(url)
    SQLModel.metadata.create_all(engine)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    TestDatabase(session=SessionLocal()).populate_test_data()
    yield url
    SQLModel.metadata.drop_all(engine)

@pytest.fixture
def authenticated_client(create_and_delete_database):
    test_db_url = create_and_delete_database
    
    async def override_get_session_real():
        from sqlmodel.ext.asyncio.session import AsyncSession
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.orm import sessionmaker
        
        async_url = test_db_url.replace("postgresql+psycopg://", "postgresql+psycopg_async://")
        engine = create_async_engine(async_url)
        
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            yield session
    """Client with mocked authentication"""
    app.dependency_overrides[get_current_user] = override_get_my_info
    app.dependency_overrides[oauth2_scheme] = override_oauth2_scheme
    app.dependency_overrides[get_session] = override_get_session_real
    yield client
    app.dependency_overrides.clear()
    
@pytest.fixture
def unauthenticated_client(create_and_delete_database):
    test_db_url = create_and_delete_database
    
    async def override_get_session_real():
        from sqlmodel.ext.asyncio.session import AsyncSession
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.orm import sessionmaker
        
        async_url = test_db_url.replace("postgresql+psycopg://", "postgresql+psycopg_async://")
        engine = create_async_engine(async_url)
        
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            yield session
    """Client without authentication"""
    app.dependency_overrides[get_session] = override_get_session_real
    yield client
    app.dependency_overrides.clear()