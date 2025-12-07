from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


from app.core.database import SessionDep, init_db
from app.core.rate_limit import setup_rate_limiting, cleanup_rate_limiting
from app.core.security_headers import setup_security_headers
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
    cleanup_rate_limiting()


app = FastAPI(lifespan=lifespan)

# Setup rate limiting middleware
setup_rate_limiting(app)

# Setup security headers middleware
setup_security_headers(app)


# UserStatusException handler removed - now using secure generic error responses
# to prevent user enumeration attacks


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

# Add these to your main.py:

@app.get("/health")
async def health_check():
    """Health check for Docker healthcheck"""
    from datetime import datetime, timezone
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "maktaba-api"
    }

@app.get("/readiness")
async def readiness_check(session: SessionDep):
    """Readiness check with database connectivity"""
    from datetime import datetime, timezone
    from sqlmodel import select
    
    try:
        await session.exec(select(1))
        return {
            "status": "ready",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(500, {"status": "not_ready", "error": str(e)})


if __name__ == "__main__":
    import uvicorn
    from app.core.settings import settings
    uvicorn.run(app, host="0.0.0.0", port=settings.port)
