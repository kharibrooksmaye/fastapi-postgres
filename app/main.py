from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import SessionDep
from app.src.routes import auth, circulation, items, users
from app.core.database import init_db

origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:3000",
    "http://localhost:5173",
]


async def startup() -> SessionDep:
    await init_db()
    # async with session_context() as session:
    #     print("Custom db actions")
    #     await custom_db_edits(session)
    #     print("Database seeding completed successfully!")


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(circulation.router, prefix="/circulation")
app.include_router(items.router, prefix="/catalog")
app.include_router(users.router, prefix="/users")
app.include_router(auth.router, prefix="/auth")


@app.get("/")
async def read_root():
    return {"Hello": "World"}
