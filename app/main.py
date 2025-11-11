from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import SessionDep, init_db
from app.src.jobs.fines_scheduler import start_scheduler, stop_scheduler
from app.src.routes import auth, circulation, fines, items, users

# Import all models to ensure they're registered with SQLModel metadata
from app.src.models import CatalogEvent, Fines, Item, RefreshToken, User  # noqa: F401

origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:3000",
    "http://localhost:5173",
    "https://maktaba-frontend.onrender.com",
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
    start_scheduler()
    print("DB connected")
    yield
    # Shutdown code
    print("Shutting down...")
    stop_scheduler()


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
app.include_router(fines.router, prefix="/fines")


@app.get("/")
async def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    import uvicorn
    from app.core.settings import settings
    uvicorn.run(app, host="0.0.0.0", port=settings.port)
