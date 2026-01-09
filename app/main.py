from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import SessionDep, init_db
from app.core.rate_limit import setup_rate_limiting, cleanup_rate_limiting
from app.core.security_headers import setup_security_headers
from app.core.middleware import setup_middleware
from app.core.monitoring import router as monitoring_router
from app.core.logging import app_logger
from app.src.jobs.fines_scheduler import start_scheduler, stop_scheduler
from app.src.routes import auth, circulation, fines, items, users

# Import all models to ensure they're registered with SQLModel metadata
from app.src.models import CatalogEvent, Fines, Item, RefreshToken, User  # noqa: F401

origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:3000",
    "http://localhost:5173",
    "https://maktaba-frontend-ifpsl.ondigitalocean.app",
]


async def startup() -> SessionDep:
    app_logger.info("Initializing database connection...")
    await init_db()
    app_logger.info("Database initialization completed successfully")
    # async with session_context() as session:
    #     print("Custom db actions")
    #     await custom_db_edits(session)
    #     print("Database seeding completed successfully!")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup code
    app_logger.info("Application startup initiated")
    try:
        await startup()
        start_scheduler()
        app_logger.info("Application startup completed successfully")
        app_logger.info("Services: Database connected, Rate limiting active, Scheduler started")
        yield
    except Exception as e:
        app_logger.error(f"Application startup failed: {str(e)}", exc_info=True)
        raise
    finally:
        # Shutdown code
        app_logger.info("Application shutdown initiated")
        stop_scheduler()
        cleanup_rate_limiting()
        app_logger.info("Application shutdown completed")


app = FastAPI(
    title="Maktabi API",
    description="Library Management System with Comprehensive Security",
    version="1.0.0",
    lifespan=lifespan
)

# Setup comprehensive middleware (includes error handling, logging, and security)
setup_middleware(app)

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

# Include monitoring endpoints (health checks, metrics)
app.include_router(monitoring_router)

# Include application routes
app.include_router(circulation.router, prefix="/circulation", tags=["circulation"])
app.include_router(items.router, prefix="/catalog", tags=["catalog"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(auth.router, prefix="/auth", tags=["authentication"])
app.include_router(fines.router, prefix="/fines", tags=["fines"])


@app.get("/")
async def read_root():
    """Root endpoint with service information."""
    from datetime import datetime, timezone
    return {
        "service": "Maktabi API",
        "description": "Library Management System with Enterprise Security",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/monitoring/health"
    }

# Legacy health endpoints for backward compatibility
@app.get("/health")
async def legacy_health_check():
    """Legacy health check endpoint - redirects to comprehensive monitoring."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/monitoring/health")

@app.get("/readiness")  
async def legacy_readiness_check():
    """Legacy readiness check endpoint - redirects to comprehensive monitoring."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/monitoring/health/ready")


if __name__ == "__main__":
    import uvicorn
    from app.core.settings import settings
    uvicorn.run(app, host="0.0.0.0", port=settings.port)
