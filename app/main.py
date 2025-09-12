from contextlib import asynccontextmanager

from functools import lru_cache
from typing import Union
from fastapi import FastAPI
from pydantic import BaseModel

from app.core.database import SessionDep, get_session, session_context
from app.mocks.mock_data import seed_database
from app.src.routes import auth, items, users
from app.core.database import init_db



async def startup() -> SessionDep:
    await init_db()
    async with session_context() as session:
        print("Seeding database with mock data...")
        await seed_database(session)
        print("Database seeding completed successfully!")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup code
    print("Starting up...")
    session = await startup()
    print("DB connected")
    yield
    # Shutdown code
    print("Shutting down...")

app = FastAPI(lifespan=lifespan)
app.include_router(items.router, prefix="/items")
app.include_router(users.router, prefix="/users")
app.include_router(auth.router, prefix="/auth")

@app.get("/")
async def read_root():
    return {"Hello": "World"}