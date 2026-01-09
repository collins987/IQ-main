# app/config.py
import os
import logging

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"

# MILESTONE 8: Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
# Map string to logging level
LOG_LEVEL = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Short-lived access token
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Longer-lived refresh token
MAX_SESSIONS_PER_USER = 3  # Limit concurrent sessions
MAX_LOGIN_ATTEMPTS = 5  # Failed attempts before lockout
LOGIN_ATTEMPT_WINDOW_MINUTES = 15  # Time window for rate limiting

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
            "admin.dashboard",
            "admin.disable_user",
            "admin.enable_user",
            "admin.view_audit_logs",
            "admin.manage_organization",
            "users.create",
            "users.read_all",
            "users.update_any",
            "users.delete_any",
            "analytics.read",
            "analytics.write",
            "profile.read_own",
            "profile.update_own",
        ]
    },
    "analyst": {
        "description": "Data analysis access - read/write analysis, view reports",
        "permissions": [
            "analytics.read",
            "analytics.write",
            "analytics.export",
            "profile.read_own",
            "profile.update_own",
            "users.read_own_org",
        ]
    },
    "viewer": {
        "description": "Read-only access - view own profile and limited data",
        "permissions": [
            "profile.read_own",
            "profile.update_own",
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
