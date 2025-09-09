from typing import Union
from fastapi import FastAPI
from pydantic import BaseModel

from app.src.routes import items, users


app = FastAPI()

app.include_router(items.router, prefix="/items")
app.include_router(users.router, prefix="/users")
@app.get("/")
async def read_root():
    return {"Hello": "World"}