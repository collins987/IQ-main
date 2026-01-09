"""
Event schemas for SentinelIQ risk engine.
Implements FAPI-aligned event structure with device fingerprinting and geo-velocity tracking.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from uuid import uuid4


class ActorContext(BaseModel):
    """Actor context - user, device, and network information."""
    
    user_id: str
    ip_address: str
    user_agent: str
    device_fingerprint: str = Field(
        ..., 
        description="Hash of device characteristics (browser, OS, screen resolution, etc.)"
    )
    session_id: Optional[str] = None
    

class GeoContext(BaseModel):
    """Geographical context for velocity and anomaly detection."""
    
    geo_lat: float
    geo_lon: float
    country_code: Optional[str] = None
    city: Optional[str] = None


class EventPayload(BaseModel):
    """Event-specific payload (varies by event type)."""
    
    model_config = {"extra": "allow"}  # Allow additional fields per event type


class AuthenticationPayload(EventPayload):
    """Authentication event payload."""
    success: bool
    method: str  # "password", "mfa", "passwordless"
    mfa_used: bool
    session_age_seconds: Optional[int] = None


class TransactionPayload(EventPayload):
    """Transaction event payload."""
    amount: float
    currency: str = "USD"
    recipient_id: Optional[str] = None
    transaction_type: str  # "transfer", "payment", "withdrawal"


class DataAccessPayload(EventPayload):
    """Data access event payload."""
    resource_type: str
    resource_id: str
    action: str  # "read", "write", "delete"


class SentinelEvent(BaseModel):
    """
    Core SentinelIQ Event Model.
    Every action that flows through SentinelIQ is an event.
    """
    
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str = Field(
        ..., 
        description="Type: authentication.login, transaction.attempted, data_access.read, etc."
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Actor info
    actor: ActorContext
    
    # Geo info
    context: GeoContext
    
    # Event-specific payload
    payload: Dict[str, Any] = Field(default_factory=dict)
    
    # Outbox tracking
    event_outbox_id: Optional[str] = None  # Links to postgres outbox table
    is_processed: bool = False
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "550e8400-e29b-41d4-a716-446655440000",
                "event_type": "authentication.login",
                "timestamp": "2025-01-10T10:22:00Z",
                "actor": {
                    "user_id": "u_123",
                    "ip_address": "102.12.34.56",
                    "user_agent": "Mozilla/5.0...",
                    "device_fingerprint": "hash_xyz",
                    "session_id": "sess_abc"
                },
                "context": {
                    "geo_lat": 40.7128,
                    "geo_lon": -74.0060,
                    "country_code": "US",
                    "city": "New York"
                },
                "payload": {
                    "success": True,
                    "method": "password",
                    "mfa_used": True,
                    "session_age_seconds": 0
                }
            }
        }


class RiskScore(BaseModel):
    """Risk scoring result."""
    
    event_id: str
    user_id: str
    risk_level: str = Field(..., description="low, medium, high, critical")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="0.0 to 1.0 confidence")
    
    # Breakdown of what contributed to the score
    hard_rules_triggered: list[str] = []  # e.g., ["sanctioned_region"]
    velocity_alerts: list[str] = []  # e.g., ["impossible_travel"]
    behavioral_flags: list[str] = []  # e.g., ["unusual_amount"]
    
    # Recommended action
    recommended_action: str = Field(
        ..., 
        description="allow, review, challenge, block"
    )
    
    # Supporting metadata
    confidence: float = Field(..., ge=0.0, le=1.0)
    triggered_rules: list[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuditLogEntry(BaseModel):
    """Immutable audit log entry with crypto-chaining."""
    
    log_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # What happened
    event_id: str
    event_type: str
    user_id: str
    action: str
    
    # Risk decision
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    decision: str  # allow, review, challenge, block
    
    # Crypto-chaining (tamper detection)
    previous_hash: Optional[str] = None  # SHA-256 of previous entry
    current_hash: Optional[str] = None  # SHA-256 of this entry
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_schema_extra = {
            "description": "Immutable log entry. Hash chain prevents tampering."
        }


class DeviceFingerprintPayload(BaseModel):
    """Device fingerprint calculation payload."""
    
    user_agent: str
    accept_language: Optional[str] = None
    accept_encoding: Optional[str] = None
    ip_address: str
    screen_resolution: Optional[str] = None  # "1920x1080"
    timezone: Optional[str] = None
    canvas_fingerprint: Optional[str] = None
    webgl_fingerprint: Optional[str] = None


class VelocityCheckRequest(BaseModel):
    """Request to check impossible travel velocity."""
    
    user_id: str
    from_location: tuple[float, float]  # (lat, lon)
    to_location: tuple[float, float]
    from_time: datetime
    to_time: datetime


class VelocityCheckResult(BaseModel):
    """Result of velocity check."""
    
    is_impossible: bool
    distance_miles: float
    travel_time_hours: float
    required_speed_mph: float
    max_human_speed: float = 500  # mph, assuming airplane travel
    alert_level: str = Field(...)  # safe, suspicious, impossible


# Event type constants
class EventTypes:
    AUTHENTICATION_LOGIN = "authentication.login"
    AUTHENTICATION_LOGOUT = "authentication.logout"
    AUTHENTICATION_FAILED = "authentication.failed"
    AUTHENTICATION_MFA = "authentication.mfa"
    
    TRANSACTION_ATTEMPTED = "transaction.attempted"
    TRANSACTION_COMPLETED = "transaction.completed"
    TRANSACTION_FAILED = "transaction.failed"
    
    DATA_ACCESS_READ = "data_access.read"
    DATA_ACCESS_WRITE = "data_access.write"
    DATA_ACCESS_DELETE = "data_access.delete"
    
    RBAC_VIOLATION = "rbac.violation"
    PASSWORD_RESET = "password.reset"
    EMAIL_VERIFIED = "email.verified"
