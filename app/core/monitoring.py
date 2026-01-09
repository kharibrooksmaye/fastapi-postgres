"""
Monitoring and health check endpoints.

This module provides comprehensive health checks, metrics collection,
and monitoring endpoints for production observability.
"""

import asyncio
import psutil
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import select, text

from app.core.database import session_context
from app.core.logging import performance_event_logger, app_logger
from app.core.settings import settings


router = APIRouter(prefix="/monitoring", tags=["monitoring"])


class HealthStatus:
    """Health status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


async def check_database_health() -> Dict[str, Any]:
    """Check database connectivity and performance."""
    try:
        start_time = time.time()
        
        async with session_context() as session:
            # Test basic connectivity
            result = await session.exec(text("SELECT 1"))
            result.first()
            
            # Test database version
            version_result = await session.exec(text("SELECT version()"))
            db_version = version_result.first()
            
            # Test connection pool status
            pool_info = session.connection().engine.pool.status()
            
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        status = HealthStatus.HEALTHY
        if response_time > 1000:  # 1 second threshold
            status = HealthStatus.DEGRADED
        
        return {
            "status": status,
            "response_time_ms": round(response_time, 2),
            "database_version": str(db_version) if db_version else "unknown",
            "connection_pool": pool_info,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        app_logger.error(f"Database health check failed: {str(e)}")
        return {
            "status": HealthStatus.UNHEALTHY,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


async def check_system_health() -> Dict[str, Any]:
    """Check system resource health."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        
        # System load
        load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
        
        # Determine overall system status
        status = HealthStatus.HEALTHY
        if cpu_percent > 80 or memory_percent > 85 or disk_percent > 90:
            status = HealthStatus.DEGRADED
        if cpu_percent > 95 or memory_percent > 95 or disk_percent > 95:
            status = HealthStatus.UNHEALTHY
        
        return {
            "status": status,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "disk_percent": disk_percent,
            "load_average": load_avg,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        app_logger.error(f"System health check failed: {str(e)}")
        return {
            "status": HealthStatus.UNHEALTHY,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


async def check_application_health() -> Dict[str, Any]:
    """Check application-specific health metrics."""
    try:
        app_settings = settings
        
        # Check configuration
        config_status = HealthStatus.HEALTHY
        config_issues = []
        
        if not getattr(app_settings, "DATABASE_URL", None):
            config_issues.append("DATABASE_URL not configured")
            config_status = HealthStatus.UNHEALTHY
        
        if not getattr(app_settings, "SECRET_KEY", None) or len(getattr(app_settings, "SECRET_KEY", "")) < 32:
            config_issues.append("SECRET_KEY too weak or missing")
            config_status = HealthStatus.DEGRADED
        
        return {
            "status": config_status,
            "environment": getattr(app_settings, "ENVIRONMENT", "unknown"),
            "debug_mode": getattr(app_settings, "DEBUG", False),
            "version": getattr(settings, "VERSION", "1.0.0"),
            "config_issues": config_issues,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        app_logger.error(f"Application health check failed: {str(e)}")
        return {
            "status": HealthStatus.UNHEALTHY,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@router.get("/health")
async def health_check():
    """
    Comprehensive health check endpoint.
    
    Returns the overall health status of the application including:
    - Database connectivity
    - System resources
    - Application configuration
    """
    try:
        # Run all health checks concurrently
        database_health, system_health, app_health = await asyncio.gather(
            check_database_health(),
            check_system_health(),
            check_application_health(),
            return_exceptions=True
        )
        
        # Handle exceptions from health checks
        if isinstance(database_health, Exception):
            database_health = {"status": HealthStatus.UNHEALTHY, "error": str(database_health)}
        if isinstance(system_health, Exception):
            system_health = {"status": HealthStatus.UNHEALTHY, "error": str(system_health)}
        if isinstance(app_health, Exception):
            app_health = {"status": HealthStatus.UNHEALTHY, "error": str(app_health)}
        
        # Determine overall status
        statuses = [
            database_health.get("status"),
            system_health.get("status"),
            app_health.get("status")
        ]
        
        if HealthStatus.UNHEALTHY in statuses:
            overall_status = HealthStatus.UNHEALTHY
            status_code = 503  # Service Unavailable
        elif HealthStatus.DEGRADED in statuses:
            overall_status = HealthStatus.DEGRADED
            status_code = 200  # OK but with warnings
        else:
            overall_status = HealthStatus.HEALTHY
            status_code = 200
        
        response = {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                "database": database_health,
                "system": system_health,
                "application": app_health
            }
        }
        
        # Log health check results
        app_logger.info(
            f"Health check completed: {overall_status}",
            extra={
                "event_type": "health_check",
                "overall_status": overall_status,
                "database_status": database_health.get("status"),
                "system_status": system_health.get("status"),
                "application_status": app_health.get("status")
            }
        )
        
        return response, status_code
        
    except Exception as e:
        app_logger.error(f"Health check endpoint failed: {str(e)}")
        return {
            "status": HealthStatus.UNHEALTHY,
            "error": "Health check system failure",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, 503


@router.get("/health/ready")
async def readiness_check():
    """
    Kubernetes readiness probe endpoint.
    
    Returns 200 if the application is ready to serve traffic,
    503 if it's not ready yet.
    """
    try:
        # Check only critical dependencies for readiness
        database_health = await check_database_health()
        
        if database_health.get("status") == HealthStatus.UNHEALTHY:
            raise HTTPException(
                status_code=503,
                detail="Service not ready - database unavailable"
            )
        
        return {
            "status": "ready",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Readiness check failed: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail="Service not ready - internal error"
        )


@router.get("/health/live")
async def liveness_check():
    """
    Kubernetes liveness probe endpoint.
    
    Returns 200 if the application process is alive and functioning,
    500+ if it should be restarted.
    """
    try:
        # Basic application liveness check
        current_time = datetime.now(timezone.utc)
        
        return {
            "status": "alive",
            "timestamp": current_time.isoformat(),
            "uptime_seconds": time.process_time()
        }
        
    except Exception as e:
        app_logger.error(f"Liveness check failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Application not responding"
        )


@router.get("/metrics")
async def application_metrics():
    """
    Application metrics endpoint for monitoring systems.
    
    Returns key performance and operational metrics.
    """
    try:
        start_time = time.time()
        
        # System metrics
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Database metrics
        db_metrics = {}
        try:
            async with session_context() as session:
                # Connection pool status
                pool = session.connection().engine.pool
                db_metrics = {
                    "pool_size": pool.size(),
                    "checked_in": pool.checkedin(),
                    "checked_out": pool.checkedout(),
                    "overflow": pool.overflow(),
                    "invalid": pool.invalid()
                }
        except Exception as e:
            db_metrics = {"error": str(e)}
        
        # Application metrics
        app_metrics = {
            "environment": getattr(settings, "ENVIRONMENT", "unknown"),
            "debug_mode": getattr(settings, "DEBUG", False),
            "response_time_ms": round((time.time() - start_time) * 1000, 2)
        }
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_mb": memory.available // (1024 * 1024),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free // (1024 * 1024 * 1024)
            },
            "database": db_metrics,
            "application": app_metrics
        }
        
    except Exception as e:
        app_logger.error(f"Metrics endpoint failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Metrics collection failed"
        )


@router.get("/status")
async def service_status():
    """
    Service status endpoint with detailed component information.
    """
    try:
        app_settings = settings
        
        return {
            "service": "maktabi-api",
            "version": getattr(app_settings, "VERSION", "1.0.0"),
            "environment": getattr(app_settings, "ENVIRONMENT", "unknown"),
            "status": "operational",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "build_info": {
                "python_version": f"{psutil.sys.version_info.major}.{psutil.sys.version_info.minor}.{psutil.sys.version_info.micro}",
                "platform": psutil.platform.platform()
            }
        }
        
    except Exception as e:
        app_logger.error(f"Status endpoint failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Status check failed"
        )