from contextlib import asynccontextmanager
from fastapi import FastAPI, Response, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import text
from app.api import auth
from app.routes import users, admin, email_verification, password_reset, analytics, events, dashboard
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.request_logging import RequestLoggingMiddleware, UserTrackingMiddleware
from app.middleware.pii_scrubber import PIIScrubberMiddleware
from app.middleware.rate_limiter import RateLimitMiddleware
from app.core.db import init_db, SessionLocal, engine
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, REGISTRY
from prometheus_fastapi_instrumentator import Instrumentator
from app.models import Base
from app.core.seed import seed_all
from app.core.logging import logger
from app.services.graph_service import router as graph_router
from app.services.message_center import router as message_router
import traceback


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    
    Handles startup and shutdown of:
    - Database initialization
    - Kafka connections (optional)
    - Vault client (optional)
    """
    # Startup - Database (required)
    try:
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            # Seed all required data (org, system user, admin)
            seed_result = seed_all(db)
            logger.info(
                f"Application startup - database initialized, "
                f"system user: {seed_result['system_user'].id}"
            )
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise RuntimeError(f"Cannot start without database: {e}")
    
    # Initialize Kafka (optional - graceful degradation)
    try:
        from app.services.kafka_service import get_kafka_producer
        await get_kafka_producer()
        logger.info("Kafka producer initialized")
    except Exception as e:
        logger.warning(f"Kafka initialization skipped: {e}")
    
    # Initialize Vault (optional - graceful degradation)
    try:
        from app.core.vault_client import get_vault_client
        vault = get_vault_client()
        if vault.is_authenticated():
            logger.info("Vault client authenticated")
    except Exception as e:
        logger.warning(f"Vault initialization skipped: {e}")
    
    # Initialize Redis Stream Manager (optional - graceful degradation)
    try:
        from app.services.redis_stream import get_redis_stream_manager
        redis_manager = get_redis_stream_manager()
        if redis_manager.health_check():
            logger.info("Redis stream manager initialized")
    except Exception as e:
        logger.warning(f"Redis initialization skipped: {e}")
    
    yield
    
    # Shutdown
    try:
        from app.services.kafka_service import shutdown_kafka
        await shutdown_kafka()
        logger.info("Kafka connections closed")
    except Exception:
        pass
    
    logger.info("Application shutdown")


app = FastAPI(
    title="SentinelIQ",
    description="Fintech Risk & Security Intelligence Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# Print all registered routes on startup
@app.on_event("startup")
async def log_registered_routes():
    from starlette.routing import WebSocketRoute
    route_list = []
    for route in app.routes:
        if hasattr(route, 'path'):
            route_type = type(route).__name__
            route_list.append(f"{route_type}: {getattr(route, 'path', '')}")
    for route in app.router.routes:
        if hasattr(route, 'path'):
            route_type = type(route).__name__
            route_list.append(f"{route_type}: {getattr(route, 'path', '')}")
    logger.info("Registered routes (including WebSockets):\n" + "\n".join(route_list))

# Initialize Prometheus instrumentator BEFORE middleware setup
Instrumentator().instrument(app).expose(app)

# ============================================================================
# Middleware Stack (order matters - last added = first executed)
# ============================================================================

# 5. User tracking (innermost - runs last on request, first on response)
app.add_middleware(UserTrackingMiddleware)

# 4. Request logging
app.add_middleware(RequestLoggingMiddleware)

# 3. PII Scrubbing (ensures no sensitive data in logs)
app.add_middleware(PIIScrubberMiddleware)

# 2. Rate limiting
app.add_middleware(RateLimitMiddleware)

# 1. Security headers (outermost - runs first on request, last on response)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "api.sentineliq.com", "sentineliq_api", "api"]
)

# ============================================================================
# Core Routes
# ============================================================================
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(auth.router)
app.include_router(email_verification.router)  # MILESTONE 6: Step 3
app.include_router(password_reset.router)  # MILESTONE 6: Step 4
app.include_router(analytics.router)  # MILESTONE 8: Analytics & monitoring
app.include_router(events.router)  # Event processing routes
app.include_router(dashboard.router)  # Admin Dashboard API

# ============================================================================
# New Feature Routes
# ============================================================================
app.include_router(graph_router)  # Graph visualization API
app.include_router(message_router)  # Secure message center

init_db()


# ============================================================================
# Global Exception Handlers
# ============================================================================

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with structured response."""
    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail}",
        extra={"path": request.url.path, "method": request.method}
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "detail": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with detailed response."""
    logger.warning(
        f"Validation error on {request.url.path}",
        extra={"errors": exc.errors()}
    )
    return JSONResponse(
        status_code=422,
        content={
            "error": True,
            "detail": "Validation error",
            "errors": exc.errors()
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler.
    Prevents crashes from unhandled exceptions.
    """
    error_id = f"ERR-{id(exc)}"
    logger.error(
        f"Unhandled exception [{error_id}]: {type(exc).__name__}: {exc}",
        extra={
            "path": request.url.path,
            "method": request.method,
            "error_id": error_id,
            "traceback": traceback.format_exc()
        }
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "detail": "Internal server error",
            "error_id": error_id
        }
    )


@app.get("/health")
def health_check():
    """Health check endpoint for load balancers."""
    return {"status": "ok", "version": "2.0.0"}


@app.get("/health/detailed")
async def detailed_health_check():
    """
    Detailed health check with component status.
    
    Checks database, Redis, Kafka, and Vault connectivity.
    """
    health_status = {
        "status": "ok",
        "version": "2.0.0",
        "components": {}
    }
    
    # Database check
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        health_status["components"]["database"] = "healthy"
    except Exception as e:
        health_status["components"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Redis check
    try:
        from app.services.redis_stream import get_redis_stream_manager
        redis_manager = get_redis_stream_manager()
        if redis_manager.health_check():
            health_status["components"]["redis"] = "healthy"
        else:
            health_status["components"]["redis"] = "unhealthy: ping failed"
            health_status["status"] = "degraded"
    except Exception as e:
        health_status["components"]["redis"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Kafka check (optional)
    try:
        from app.services.kafka_service import _producer
        if _producer and _producer._started:
            health_status["components"]["kafka"] = "healthy"
        else:
            health_status["components"]["kafka"] = "not_configured"
    except Exception:
        health_status["components"]["kafka"] = "not_configured"
    
    # Vault check (optional)
    try:
        from app.core.vault_client import get_vault_client
        vault = get_vault_client()
        if vault.is_authenticated():
            health_status["components"]["vault"] = "healthy"
        else:
            health_status["components"]["vault"] = "not_authenticated"
    except Exception:
        health_status["components"]["vault"] = "not_configured"
    
    return health_status


@app.get("/metrics", include_in_schema=False)
def get_metrics():
    """Prometheus metrics endpoint - returns metrics in text/plain format"""
    metrics_output = generate_latest(REGISTRY)
    # Ensure proper encoding if bytes are returned
    if isinstance(metrics_output, bytes):
        metrics_output = metrics_output.decode('utf-8')
    return Response(
        content=metrics_output,
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )

