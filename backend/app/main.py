from fastapi import FastAPI, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.api import auth
from app.routes import users, admin, email_verification, password_reset, analytics
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.request_logging import RequestLoggingMiddleware, UserTrackingMiddleware
from app.core.db import init_db, SessionLocal, engine
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, REGISTRY
from prometheus_fastapi_instrumentator import Instrumentator
from app.models import Base
from app.core.seed import seed_default_org
from app.core.logging import logger
import time

app = FastAPI(
    title="SentinelIQ",
    description="Fintech Risk & Security Intelligence Platform"
)

# Initialize Prometheus instrumentator BEFORE middleware setup
Instrumentator().instrument(app).expose(app)

# MILESTONE 8: Logging and request tracking middleware
app.add_middleware(UserTrackingMiddleware)
app.add_middleware(RequestLoggingMiddleware)

# Security middleware (OWASP hardening)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "api.sentineliq.com", "sentineliq_api", "api"]
)

# Routes
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(auth.router)
app.include_router(email_verification.router)  # MILESTONE 6: Step 3
app.include_router(password_reset.router)  # MILESTONE 6: Step 4
app.include_router(analytics.router)  # MILESTONE 8: Analytics & monitoring
init_db()

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_default_org(db)
        logger.info("Application startup - database initialized")
    finally:
        db.close()

@app.on_event("shutdown")
def shutdown():
    logger.info("Application shutdown")

@app.get("/health")
def health_check():
    return {"status": "ok"}

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
