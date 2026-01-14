# app/config.py
"""
SentinelIQ Configuration Module

Centralizes all configuration with:
- Environment variable loading
- Type validation
- Sensible defaults
- Settings class for dependency injection

Compliance: Follows 12-factor app methodology
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# ============================================================================
# Authentication Configuration
# ============================================================================
# Development mode flag - enables test user and debug features
DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

# Universal Admin Credentials (environment-based, NOT stored in database)
# Used for bootstrap access and emergency recovery
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@sentineliq.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@SentinelIQ#2025")

# Dummy Test User (only active when DEV_MODE=true)
# Non-persistent, exists only in memory for testing
TEST_USER_EMAIL = os.getenv("TEST_USER_EMAIL", "user@test.sentineliq.local")
TEST_USER_PASSWORD = os.getenv("TEST_USER_PASSWORD", "UserTest@123")

# ============================================================================
# Token Configuration
# ============================================================================
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Short-lived access token
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Longer-lived refresh token
MAX_SESSIONS_PER_USER = 3  # Limit concurrent sessions
MAX_LOGIN_ATTEMPTS = 5  # Failed attempts before lockout
LOGIN_ATTEMPT_WINDOW_MINUTES = 15  # Time window for rate limiting

# MILESTONE 8: Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
# Map string to logging level
LOG_LEVEL = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

# MILESTONE 6: Identity Hardening
EMAIL_TOKEN_EXPIRE_MINUTES = 24 * 60  # 24 hours (email verification)
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes (short for security)

# Email Configuration (Step 5)
EMAIL_FROM = os.getenv("EMAIL_FROM", "no-reply@sentineliq.local")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))  # MailHog default
SMTP_USERNAME = os.getenv("SMTP_USERNAME", None)
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", None)
SMTP_TLS = os.getenv("SMTP_TLS", "false").lower() == "true"

# Frontend configuration for email links
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")

# MILESTONE 7: Role-Based Access Control (RBAC)
# Role hierarchy: admin > analyst > viewer
ROLES = {
    "admin": {
        "description": "Full system access - manage users, settings, audit logs",
        "permissions": [
            # Admin permissions
            "admin.dashboard",
            "admin.disable_user",
            "admin.enable_user",
            "admin.view_audit_logs",
            "admin.manage_organization",
            # User management (full access)
            "users.create",
            "users.read_all",
            "users.read_global",      # NEW: View system/global users
            "users.read_metadata",    # NEW: View user metadata (device, login info)
            "users.read_audit",       # NEW: View user access audit logs
            "users.update_any",
            "users.delete_any",
            "users.manage",           # NEW: Full user management (status, visibility)
            # Analytics
            "analytics.read",
            "analytics.write",
            # Profile
            "profile.read_own",
            "profile.update_own",
        ]
    },
    "analyst": {
        "description": "Data analysis access - view user profiles with metadata, read/write analysis",
        "permissions": [
            # Analytics
            "analytics.read",
            "analytics.write",
            "analytics.export",
            # Profile
            "profile.read_own",
            "profile.update_own",
            # User access (can view users with more detail than viewer)
            "users.read_own_org",     # View org users with metadata
            "users.read_global",      # View system users with metadata
            "users.read_public",      # View public user profiles
            "users.read_metadata",    # Can see user metadata (login info, risk score)
        ]
    },
    "viewer": {
        "description": "Read-only access - view user profiles with limited/redacted fields",
        "permissions": [
            "profile.read_own",
            "profile.update_own",
            "users.read_global",      # Can view system users (public fields only)
            "users.read_public",      # View public user profiles (redacted)
            "users.read_own_org",     # Can view users in same organization (public fields)
        ]
    }
}

# Permission-to-role mapping (reverse lookup)
PERMISSION_ROLES = {}
for role, config in ROLES.items():
    for permission in config.get("permissions", []):
        if permission not in PERMISSION_ROLES:
            PERMISSION_ROLES[permission] = []
        PERMISSION_ROLES[permission].append(role)

# ============================================================================
# MILESTONE 1 & 2: Event-Driven Risk Engine Configuration
# ============================================================================

# Redis Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# Event Streams
EVENT_STREAM_NAME = "sentineliq:events"
RISK_STREAM_NAME = "sentineliq:risk_decisions"
ALERT_STREAM_NAME = "sentineliq:alerts"

# Risk Engine
RISK_ENGINE_RULES_PATH = os.getenv("RISK_RULES_PATH", "/app/rules/fraud_rules.yaml")
RISK_ENGINE_ENABLED = os.getenv("RISK_ENGINE_ENABLED", "true").lower() == "true"
RISK_DECISION_LATENCY_SLA_MS = 200  # Target decision time

# MinIO/S3 Configuration (for immutable audit logs)
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "sentineliq-audit-logs")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

# Vault Configuration (secret management)
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "devroot")
VAULT_SECRET_PATH = os.getenv("VAULT_SECRET_PATH", "secret/data/sentineliq")

# Metrics
METRICS_ENABLED = os.getenv("METRICS_ENABLED", "true").lower() == "true"
PROMETHEUS_METRICS_PORT = int(os.getenv("PROMETHEUS_METRICS_PORT", "8001"))

# Observability
LOKI_ENABLED = os.getenv("LOKI_ENABLED", "true").lower() == "true"
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")

# Risk Thresholds
RISK_THRESHOLDS = {
    "allow": 0.0,      # Risk score < 0.30
    "review": 0.30,    # 0.30 - 0.60
    "challenge": 0.60, # 0.60 - 0.80
    "block": 0.80      # >= 0.80
}

# ============================================================================
# Kafka Configuration
# ============================================================================
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "true").lower() == "true"
KAFKA_CONSUMER_GROUP = os.getenv("KAFKA_CONSUMER_GROUP", "sentineliq-consumers")

# ============================================================================
# ML Configuration
# ============================================================================
ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "/app/models/fraud_model.pkl")
ML_ENABLED = os.getenv("ML_ENABLED", "true").lower() == "true"
ML_ANOMALY_THRESHOLD = float(os.getenv("ML_ANOMALY_THRESHOLD", "0.5"))

# ============================================================================
# Rate Limiting Configuration
# ============================================================================
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_DEFAULT_REQUESTS = int(os.getenv("RATE_LIMIT_DEFAULT_REQUESTS", "100"))
RATE_LIMIT_DEFAULT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_DEFAULT_WINDOW_SECONDS", "60"))

# ============================================================================
# ABAC Configuration
# ============================================================================
ABAC_ENABLED = os.getenv("ABAC_ENABLED", "true").lower() == "true"

# ============================================================================
# Settings Class (for dependency injection)
# ============================================================================

@dataclass
class Settings:
    """
    Application settings with type hints and defaults.
    
    Use this class for type-safe configuration access.
    """
    # Core
    secret_key: str = SECRET_KEY
    algorithm: str = ALGORITHM
    access_token_expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES
    refresh_token_expire_days: int = REFRESH_TOKEN_EXPIRE_DAYS
    
    # Redis
    redis_url: str = field(default_factory=lambda: REDIS_URL)
    
    # Database
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL", 
            "postgresql://postgres:postgres@db:5432/sentineliq"
        )
    )
    
    # Kafka
    kafka_bootstrap_servers: str = field(default_factory=lambda: KAFKA_BOOTSTRAP_SERVERS)
    kafka_enabled: bool = field(default_factory=lambda: KAFKA_ENABLED)
    
    # Vault
    vault_addr: str = field(default_factory=lambda: VAULT_ADDR)
    vault_token: str = field(default_factory=lambda: VAULT_TOKEN)
    
    # MinIO
    minio_endpoint: str = field(default_factory=lambda: MINIO_ENDPOINT)
    minio_access_key: str = field(default_factory=lambda: MINIO_ACCESS_KEY)
    minio_secret_key: str = field(default_factory=lambda: MINIO_SECRET_KEY)
    minio_secure: bool = field(default_factory=lambda: MINIO_SECURE)
    
    # ML
    ml_model_path: str = field(default_factory=lambda: ML_MODEL_PATH)
    ml_enabled: bool = field(default_factory=lambda: ML_ENABLED)
    
    # Rate Limiting
    rate_limit_enabled: bool = field(default_factory=lambda: RATE_LIMIT_ENABLED)
    
    # Email
    email_from: str = field(default_factory=lambda: EMAIL_FROM)
    smtp_host: str = field(default_factory=lambda: SMTP_HOST)
    smtp_port: int = field(default_factory=lambda: SMTP_PORT)


# Singleton settings instance
settings = Settings()
