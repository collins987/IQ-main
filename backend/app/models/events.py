"""
Database models for event ingestion, outbox pattern, and audit logging.
Implements transactional outbox for guaranteed event delivery and crypto-chained audit logs.
"""

from datetime import datetime
from sqlalchemy import Column, String, Float, Boolean, DateTime, JSON, Integer, ForeignKey, Text, Index
from sqlalchemy.orm import relationship

# Import Base from dedicated base module to avoid circular imports
from app.models.base import Base


class EventOutbox(Base):
    """Transactional outbox table for guaranteed event delivery."""
    
    __tablename__ = "event_outbox"
    
    id = Column(String(36), primary_key=True)
    event_type = Column(String(100), nullable=False, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    event_data = Column(JSON, nullable=False)  # Full SentinelEvent as JSON
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    processed_at = Column(DateTime(timezone=True), nullable=True, index=True)
    is_processed = Column(Boolean, default=False, index=True)
    retry_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    __table_args__ = (
        Index('ix_outbox_not_processed', 'is_processed', 'created_at'),
    )


class RiskDecision(Base):
    """Risk engine decisions for audit and compliance."""
    
    __tablename__ = "risk_decisions"
    
    id = Column(String(36), primary_key=True)
    event_id = Column(String(36), nullable=False, unique=True, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    event_type = Column(String(100), nullable=False)
    
    # Risk scoring
    risk_score = Column(Float, nullable=False)  # 0.0 to 1.0
    risk_level = Column(String(20), nullable=False)  # low, medium, high, critical
    
    # Decision
    decision = Column(String(20), nullable=False)  # allow, review, challenge, block
    recommended_action = Column(String(50), nullable=False)
    
    # What triggered the decision
    hard_rules_triggered = Column(JSON, default=list)  # List of rule names
    velocity_alerts = Column(JSON, default=list)
    behavioral_flags = Column(JSON, default=list)
    triggered_rules = Column(JSON, default=list)  # All triggered rule IDs
    
    # Metadata
    context_data = Column(JSON, default=dict)  # IP, geo, device, etc.
    confidence = Column(Float, nullable=False)  # 0.0 to 1.0
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('ix_risk_decision_user_time', 'user_id', 'created_at'),
    )


class CryptoAuditLog(Base):
    """Immutable, crypto-chained audit log for compliance."""
    
    __tablename__ = "crypto_audit_logs"
    
    id = Column(String(36), primary_key=True)
    sequence = Column(Integer, nullable=False, unique=True, autoincrement=True)
    
    # Event reference
    event_id = Column(String(36), nullable=False, index=True)
    event_type = Column(String(100), nullable=False)
    user_id = Column(String(36), nullable=False, index=True)
    
    # Action and decision
    action = Column(String(100), nullable=False)  # e.g., "risk_score_calculated", "alert_generated"
    decision = Column(String(50), nullable=False)  # allow, review, challenge, block
    
    # Risk context
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    
    # Crypto-chaining for tamper detection
    previous_hash = Column(String(64), nullable=True)  # SHA-256 of previous entry
    current_hash = Column(String(64), nullable=False)  # SHA-256 of this entry
    
    # Full log data (encrypted in production)
    log_data = Column(JSON, nullable=False)
    
    # Metadata
    actor_ip = Column(String(45), nullable=True)  # IPv4 or IPv6
    actor_user_agent = Column(String(500), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('ix_crypto_audit_user_time', 'user_id', 'created_at'),
        Index('ix_crypto_audit_hash_chain', 'sequence', 'current_hash'),
    )


class RuleEvaluation(Base):
    """Records which rules were evaluated for each event."""
    
    __tablename__ = "rule_evaluations"
    
    id = Column(String(36), primary_key=True)
    risk_decision_id = Column(String(36), ForeignKey('risk_decisions.id'), nullable=False)
    
    # Rule info
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(200), nullable=False)
    rule_category = Column(String(50), nullable=False)  # hard_rule, velocity, behavioral
    
    # Evaluation result
    matched = Column(Boolean, nullable=False)
    confidence = Column(Float, nullable=False)
    score_contribution = Column(Float, default=0.0)  # How much this rule added to overall risk
    
    # Rule data for debugging
    condition_values = Column(JSON, nullable=True)  # What values were checked
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class DeviceFingerprint(Base):
    """Stores device fingerprints for device-based anomaly detection."""
    
    __tablename__ = "device_fingerprints"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False, index=True)
    fingerprint_hash = Column(String(64), nullable=False, unique=True)  # SHA-256
    
    # Raw fingerprint data (encrypted at rest)
    user_agent = Column(Text, nullable=True)
    screen_resolution = Column(String(50), nullable=True)
    timezone = Column(String(50), nullable=True)
    language = Column(String(20), nullable=True)
    canvas_fingerprint = Column(String(64), nullable=True)
    webgl_fingerprint = Column(String(64), nullable=True)
    
    # Usage tracking
    first_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    usage_count = Column(Integer, default=1)
    is_trusted = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


class VelocityCounter(Base):
    """High-speed counters for velocity checks (complements Redis)."""
    
    __tablename__ = "velocity_counters"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False, index=True)
    metric_type = Column(String(50), nullable=False)  # login_attempts, transactions, etc.
    
    # Time window
    window_start = Column(DateTime(timezone=True), nullable=False, index=True)
    window_end = Column(DateTime(timezone=True), nullable=False)
    
    # Count
    count = Column(Integer, default=0)
    threshold = Column(Integer, nullable=False)
    
    is_exceeded = Column(Boolean, default=False, index=True)
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
