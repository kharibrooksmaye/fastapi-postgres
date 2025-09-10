from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Union
from fastapi import FastAPI
from pydantic import BaseModel

from app.src.routes import items, users
from app.core.database import create_db_and_tables




async def startup():
    create_db_and_tables()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup code
    print("Starting up...")
    await startup()
    print("DB connected")
    yield
    # Shutdown code
    print("Shutting down...")

app = FastAPI(lifespan=lifespan)
app.include_router(items.router, prefix="/items")
app.include_router(users.router, prefix="/users")

@app.get("/")
async def read_root():
    return {"Hello": "World"}