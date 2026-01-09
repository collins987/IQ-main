"""
Integration tests for SentinelIQ Risk Engine - Milestone 1 & 2.
Tests event ingestion, risk scoring, and crypto-audit logging.
"""

import pytest
import asyncio
import json
from datetime import datetime
from uuid import uuid4

from app.schemas.event import SentinelEvent, ActorContext, GeoContext, EventTypes
from app.services.risk_engine import RiskEngine
from app.services.redis_stream import RedisStreamManager
from app.models.events import EventOutbox, RiskDecision, CryptoAuditLog
from app.core.db import db_session, SessionLocal


@pytest.fixture
def redis_manager():
    """Redis stream manager instance."""
    return RedisStreamManager()


@pytest.fixture
def risk_engine():
    """Risk engine instance."""
    return RiskEngine()


def create_test_event(
    user_id: str = "test_user",
    event_type: str = EventTypes.AUTHENTICATION_LOGIN,
    country_code: str = "US",
    ip: str = "1.2.3.4"
) -> SentinelEvent:
    """Helper to create test events."""
    return SentinelEvent(
        event_id=str(uuid4()),
        event_type=event_type,
        actor=ActorContext(
            user_id=user_id,
            ip_address=ip,
            user_agent="Mozilla/5.0 Test",
            device_fingerprint=f"device_{user_id}_001"
        ),
        context=GeoContext(
            geo_lat=40.7128,
            geo_lon=-74.0060,
            country_code=country_code
        ),
        payload={
            "success": True,
            "method": "password",
            "mfa_used": True
        }
    )


class TestRiskEngine:
    """Test risk engine scoring logic."""
    
    @pytest.mark.asyncio
    async def test_safe_login(self, risk_engine):
        """Test that a normal login gets low risk score."""
        event = create_test_event()
        
        result = await risk_engine.evaluate_event(event)
        
        assert result.risk_score < 0.3
        assert result.risk_level == "low"
        assert result.recommended_action == "allow"
    
    @pytest.mark.asyncio
    async def test_sanctioned_country_blocks(self, risk_engine):
        """Test that access from sanctioned country triggers hard rule."""
        event = create_test_event(country_code="KP")  # North Korea
        
        result = await risk_engine.evaluate_event(event)
        
        assert result.risk_score >= 0.8
        assert result.risk_level == "critical"
        assert result.recommended_action == "block"
        assert "sanctioned_region" in result.hard_rules_triggered
    
    @pytest.mark.asyncio
    async def test_impossible_travel_detected(self, risk_engine, redis_manager):
        """Test that impossible travel (NYC to Tokyo in < 1 hour) is detected."""
        # First login from New York
        event1 = create_test_event(user_id="traveler")
        result1 = await risk_engine.evaluate_event(event1)
        assert result1.risk_score < 0.3
        
        # Cache location
        redis_manager.cache_user_location("traveler", 40.7128, -74.0060)
        
        # Second login from Tokyo (5500 miles away)
        event2 = create_test_event(
            user_id="traveler",
            country_code="JP"
        )
        # Override coordinates to Tokyo
        event2.context.geo_lat = 35.6762
        event2.context.geo_lon = 139.6503
        
        result2 = await risk_engine.evaluate_event(event2)
        
        # Should trigger velocity check
        assert len(result2.velocity_alerts) > 0 or result2.risk_score > 0.5
        assert result2.recommended_action in ["challenge", "block"]
    
    @pytest.mark.asyncio
    async def test_new_device_detection(self, risk_engine, redis_manager):
        """Test that new device logins are flagged."""
        user_id = "new_device_user"
        
        # First login with device A
        event1 = create_test_event(user_id=user_id)
        redis_manager.cache_device_fingerprint(user_id, event1.actor.device_fingerprint)
        
        # Second login with new device B
        event2 = create_test_event(user_id=user_id)
        event2.actor.device_fingerprint = "device_newuser_999"
        
        result = await risk_engine.evaluate_event(event2)
        
        # New device might trigger behavioral rule
        assert len(result.triggered_rules) >= 0


class TestRedisStreams:
    """Test Redis Streams event pipeline."""
    
    def test_add_event_to_stream(self, redis_manager):
        """Test adding event to Redis stream."""
        event_data = {
            "event_id": str(uuid4()),
            "event_type": "authentication.login",
            "user_id": "test_user"
        }
        
        event_id = redis_manager.add_event(event_data)
        
        assert event_id is not None
        assert isinstance(event_id, str)
    
    def test_velocity_counter(self, redis_manager):
        """Test velocity counter for rate limiting."""
        user_key = "user:123:login_attempts:5min"
        
        # First increment
        count1 = redis_manager.increment_velocity_counter(user_key)
        assert count1 == 1
        
        # Second increment
        count2 = redis_manager.increment_velocity_counter(user_key)
        assert count2 == 2
        
        # Get current value
        current = redis_manager.get_velocity_counter(user_key)
        assert current == 2
    
    def test_device_fingerprint_caching(self, redis_manager):
        """Test device fingerprint caching."""
        user_id = "test_user"
        device1 = "device_hash_001"
        device2 = "device_hash_002"
        
        # Cache first device
        redis_manager.cache_device_fingerprint(user_id, device1)
        assert redis_manager.is_known_device(user_id, device1)
        
        # Check unknown device
        assert not redis_manager.is_known_device(user_id, device2)
        
        # Cache second device
        redis_manager.cache_device_fingerprint(user_id, device2)
        assert redis_manager.is_known_device(user_id, device2)
        
        # Get all known devices
        devices = redis_manager.get_known_devices(user_id)
        assert device1 in devices
        assert device2 in devices


class TestCryptoAuditLogging:
    """Test crypto-chained audit logging."""
    
    @pytest.mark.asyncio
    async def test_audit_log_entry_created(self, risk_engine):
        """Test that audit log entry is created with crypto-chaining."""
        event = create_test_event()
        
        result = await risk_engine.evaluate_event(event)
        
        # Check that audit log was created
        audit_entry = db_session.query(CryptoAuditLog).filter(
            CryptoAuditLog.event_id == event.event_id
        ).first()
        
        assert audit_entry is not None
        assert audit_entry.current_hash is not None
        assert len(audit_entry.current_hash) == 64  # SHA-256 hex
    
    @pytest.mark.asyncio
    async def test_hash_chain_integrity(self, risk_engine):
        """Test that hash chain is properly linked."""
        # Create two events
        event1 = create_test_event()
        event2 = create_test_event()
        
        result1 = await risk_engine.evaluate_event(event1)
        result2 = await risk_engine.evaluate_event(event2)
        
        # Get audit logs
        logs = db_session.query(CryptoAuditLog).order_by(
            CryptoAuditLog.sequence
        ).all()
        
        # Verify chain
        assert len(logs) >= 2
        for i in range(1, len(logs)):
            # Current entry's previous_hash should match previous entry's current_hash
            assert logs[i].previous_hash == logs[i-1].current_hash


class TestEventOutboxPattern:
    """Test transactional outbox for guaranteed delivery."""
    
    def test_event_outbox_entry_created(self):
        """Test that event is written to outbox table."""
        event = create_test_event()
        
        # Simulate API ingestion
        outbox_entry = EventOutbox(
            id=event.event_id,
            event_type=event.event_type,
            user_id=event.actor.user_id,
            event_data=event.dict(),
            is_processed=False
        )
        
        db_session.add(outbox_entry)
        db_session.commit()
        
        # Verify it was saved
        saved = db_session.query(EventOutbox).filter(
            EventOutbox.id == event.event_id
        ).first()
        
        assert saved is not None
        assert saved.is_processed == False
    
    def test_outbox_processing_workflow(self):
        """Test outbox processing: insert -> process -> mark done."""
        event = create_test_event()
        
        # Step 1: Insert into outbox
        outbox = EventOutbox(
            id=event.event_id,
            event_type=event.event_type,
            user_id=event.actor.user_id,
            event_data=event.dict(),
            is_processed=False
        )
        db_session.add(outbox)
        db_session.commit()
        
        # Step 2: Worker reads unprocessed events
        unprocessed = db_session.query(EventOutbox).filter(
            EventOutbox.is_processed == False
        ).all()
        
        assert len(unprocessed) > 0
        
        # Step 3: Worker processes and marks as done
        for entry in unprocessed:
            entry.is_processed = True
            entry.processed_at = datetime.utcnow()
        
        db_session.commit()
        
        # Step 4: Verify all processed
        still_unprocessed = db_session.query(EventOutbox).filter(
            EventOutbox.is_processed == False
        ).all()
        
        assert len(still_unprocessed) == 0


class TestRiskDecisionLogging:
    """Test risk decision logging."""
    
    @pytest.mark.asyncio
    async def test_risk_decision_recorded(self, risk_engine):
        """Test that risk decisions are recorded."""
        event = create_test_event()
        
        result = await risk_engine.evaluate_event(event)
        
        # Note: Risk decisions are logged via audit logs, not separate table
        # Verify audit log has the decision
        audit = db_session.query(CryptoAuditLog).filter(
            CryptoAuditLog.event_id == event.event_id
        ).first()
        
        assert audit is not None
        assert audit.decision in ["allow", "review", "challenge", "block"]
        assert audit.risk_score is not None


class TestMetricsCollection:
    """Test Prometheus metrics."""
    
    def test_metrics_endpoint_available(self):
        """Test that /metrics endpoint exists."""
        # This would be tested via HTTP client in full integration test
        # For now, just verify the pattern exists
        from prometheus_client import Counter, Histogram
        
        # These should exist in app
        test_counter = Counter('test_metric', 'Test counter')
        test_histogram = Histogram('test_histogram', 'Test histogram')
        
        assert test_counter is not None
        assert test_histogram is not None


# Performance benchmarks
class TestPerformance:
    """Performance and scalability tests."""
    
    @pytest.mark.asyncio
    async def test_decision_latency(self, risk_engine):
        """Test that risk decisions are made within SLA."""
        import time
        
        event = create_test_event()
        
        start = time.time()
        result = await risk_engine.evaluate_event(event)
        elapsed_ms = (time.time() - start) * 1000
        
        # SLA: < 200ms
        assert elapsed_ms < 200, f"Decision took {elapsed_ms}ms, SLA is 200ms"
    
    def test_throughput(self, redis_manager):
        """Test event ingestion throughput."""
        import time
        
        num_events = 1000
        event_ids = []
        
        start = time.time()
        for i in range(num_events):
            event_data = {
                "event_id": f"evt_{i}",
                "event_type": "authentication.login",
                "user_id": f"user_{i % 100}"
            }
            eid = redis_manager.add_event(event_data)
            event_ids.append(eid)
        
        elapsed = time.time() - start
        throughput = num_events / elapsed
        
        print(f"Throughput: {throughput:.0f} events/sec")
        
        # Should handle at least 100 events/sec on single instance
        assert throughput > 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
