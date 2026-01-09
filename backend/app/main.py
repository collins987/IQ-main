from contextlib import asynccontextmanager
from fastapi import FastAPI, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.api import auth
from app.routes import users, admin, email_verification, password_reset, analytics, events
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.request_logging import RequestLoggingMiddleware, UserTrackingMiddleware
from app.middleware.pii_scrubber import PIIScrubberMiddleware
from app.middleware.rate_limiter import RateLimitMiddleware
from app.core.db import init_db, SessionLocal, engine
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, REGISTRY
from prometheus_fastapi_instrumentator import Instrumentator
from app.models import Base
from app.core.seed import seed_default_org
from app.core.logging import logger
from app.services.graph_service import router as graph_router
from app.services.message_center import router as message_router
import time


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
    # Startup
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_default_org(db)
        logger.info("Application startup - database initialized")
    finally:
        db.close()
    
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

# ============================================================================
# New Feature Routes
# ============================================================================
app.include_router(graph_router)  # Graph visualization API
app.include_router(message_router)  # Secure message center

init_db()


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
    status = {
        "status": "ok",
        "version": "2.0.0",
        "components": {}
    }
    
    # Database check
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        status["components"]["database"] = "healthy"
    except Exception as e:
        status["components"]["database"] = f"unhealthy: {str(e)}"
        status["status"] = "degraded"
    
    # Redis check
    try:
        import redis
        from app.config import settings
        r = redis.Redis.from_url(settings.redis_url)
        r.ping()
        status["components"]["redis"] = "healthy"
    except Exception as e:
        status["components"]["redis"] = f"unhealthy: {str(e)}"
        status["status"] = "degraded"
    
    # Kafka check (optional)
    try:
        from app.services.kafka_service import _producer
        if _producer and _producer._started:
            status["components"]["kafka"] = "healthy"
        else:
            status["components"]["kafka"] = "not_configured"
    except Exception:
        status["components"]["kafka"] = "not_configured"
    
    # Vault check (optional)
    try:
        from app.core.vault_client import get_vault_client
        vault = get_vault_client()
        if vault.is_authenticated():
            status["components"]["vault"] = "healthy"
        else:
            status["components"]["vault"] = "not_authenticated"
    except Exception:
        status["components"]["vault"] = "not_configured"
    
    return status


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

