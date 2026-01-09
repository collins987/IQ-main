"""
Milestone 8: Metrics Collection
Prometheus metrics for monitoring SentinelIQ
"""

from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry
import time

# Create a custom registry
REGISTRY = CollectorRegistry()

# === Authentication Metrics ===
auth_login_attempts = Counter(
    "sentineliq_auth_login_attempts_total",
    "Total login attempts",
    ["status"],  # success, failed, locked
    registry=REGISTRY
)

auth_registration_attempts = Counter(
    "sentineliq_auth_registration_attempts_total",
    "Total registration attempts",
    ["status"],  # success, failed
    registry=REGISTRY
)

auth_token_refreshes = Counter(
    "sentineliq_auth_token_refreshes_total",
    "Total token refresh attempts",
    ["status"],  # success, failed, expired
    registry=REGISTRY
)

# === Access Control Metrics ===
rbac_access_checks = Counter(
    "sentineliq_rbac_access_checks_total",
    "Total RBAC access checks",
    ["status", "role"],  # allowed, denied; admin, analyst, viewer
    registry=REGISTRY
)

forbidden_access_attempts = Counter(
    "sentineliq_forbidden_access_attempts_total",
    "Total forbidden access attempts",
    ["user_role", "resource"],
    registry=REGISTRY
)

# === API Metrics ===
api_request_duration = Histogram(
    "sentineliq_api_request_duration_seconds",
    "API request duration in seconds",
    ["method", "endpoint", "status_code"],
    registry=REGISTRY
)

api_requests_total = Counter(
    "sentineliq_api_requests_total",
    "Total API requests",
    ["method", "endpoint", "status_code"],
    registry=REGISTRY
)

api_errors_total = Counter(
    "sentineliq_api_errors_total",
    "Total API errors",
    ["method", "endpoint", "error_type"],
    registry=REGISTRY
)

# === User Metrics ===
active_users = Gauge(
    "sentineliq_active_users",
    "Number of active users",
    ["role"],  # admin, analyst, viewer
    registry=REGISTRY
)

users_online = Gauge(
    "sentineliq_users_online",
    "Number of users currently online",
    registry=REGISTRY
)

email_verified_users = Gauge(
    "sentineliq_email_verified_users",
    "Number of users with verified emails",
    registry=REGISTRY
)

# === Session Metrics ===
active_sessions = Gauge(
    "sentineliq_active_sessions",
    "Number of active sessions",
    ["user_role"],
    registry=REGISTRY
)

session_duration = Histogram(
    "sentineliq_session_duration_seconds",
    "Session duration in seconds",
    ["user_role"],
    registry=REGISTRY
)

# === Email Metrics ===
email_verification_attempts = Counter(
    "sentineliq_email_verification_attempts_total",
    "Total email verification attempts",
    ["status"],  # success, failed, expired
    registry=REGISTRY
)

email_sent_total = Counter(
    "sentineliq_email_sent_total",
    "Total emails sent",
    ["type"],  # verification, reset, notification
    registry=REGISTRY
)

# === Database Metrics ===
db_connection_pool_size = Gauge(
    "sentineliq_db_connection_pool_size",
    "Database connection pool size",
    registry=REGISTRY
)

db_query_duration = Histogram(
    "sentineliq_db_query_duration_seconds",
    "Database query duration in seconds",
    ["operation"],  # select, insert, update, delete
    registry=REGISTRY
)


class MetricsTracker:
    """Helper class for tracking metrics"""
    
    @staticmethod
    def track_login_attempt(success: bool, is_locked: bool = False) -> None:
        """Track login attempt"""
        if is_locked:
            status = "locked"
        else:
            status = "success" if success else "failed"
        auth_login_attempts.labels(status=status).inc()
    
    @staticmethod
    def track_registration(success: bool) -> None:
        """Track registration attempt"""
        status = "success" if success else "failed"
        auth_registration_attempts.labels(status=status).inc()
    
    @staticmethod
    def track_token_refresh(success: bool, expired: bool = False) -> None:
        """Track token refresh"""
        if expired:
            status = "expired"
        else:
            status = "success" if success else "failed"
        auth_token_refreshes.labels(status=status).inc()
    
    @staticmethod
    def track_rbac_check(allowed: bool, role: str) -> None:
        """Track RBAC access check"""
        status = "allowed" if allowed else "denied"
        rbac_access_checks.labels(status=status, role=role).inc()
    
    @staticmethod
    def track_forbidden_access(role: str, resource: str) -> None:
        """Track forbidden access attempt"""
        forbidden_access_attempts.labels(user_role=role, resource=resource).inc()
    
    @staticmethod
    def track_api_request(method: str, endpoint: str, status_code: int, duration: float) -> None:
        """Track API request"""
        api_request_duration.labels(method=method, endpoint=endpoint, status_code=status_code).observe(duration)
        api_requests_total.labels(method=method, endpoint=endpoint, status_code=status_code).inc()
    
    @staticmethod
    def track_api_error(method: str, endpoint: str, error_type: str) -> None:
        """Track API error"""
        api_errors_total.labels(method=method, endpoint=endpoint, error_type=error_type).inc()
    
    @staticmethod
    def track_email_verification(success: bool, expired: bool = False) -> None:
        """Track email verification attempt"""
        if expired:
            status = "expired"
        else:
            status = "success" if success else "failed"
        email_verification_attempts.labels(status=status).inc()
    
    @staticmethod
    def track_email_sent(email_type: str) -> None:
        """Track email sent"""
        email_sent_total.labels(type=email_type).inc()
    
    @staticmethod
    def update_active_users(role: str, count: int) -> None:
        """Update active users gauge"""
        active_users.labels(role=role).set(count)
    
    @staticmethod
    def update_active_sessions(role: str, count: int) -> None:
        """Update active sessions gauge"""
        active_sessions.labels(user_role=role).set(count)
    
    @staticmethod
    def track_db_query(operation: str, duration: float) -> None:
        """Track database query"""
        db_query_duration.labels(operation=operation).observe(duration)
