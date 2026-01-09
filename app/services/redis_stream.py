"""
Redis Streams integration for event-driven architecture.
Implements consumer groups for guaranteed event processing.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from redis import Redis
from redis.exceptions import ResponseError
from app.config import REDIS_URL

logger = logging.getLogger("sentineliq.redis_streams")


class RedisStreamManager:
    """Manages Redis Stream operations for event ingestion and processing."""
    
    def __init__(self, redis_url: str = REDIS_URL):
        self.redis = Redis.from_url(redis_url, decode_responses=True)
        
        # Stream names
        self.event_stream = "sentineliq:events"
        self.risk_stream = "sentineliq:risk_decisions"
        self.alert_stream = "sentineliq:alerts"
        
        # Consumer groups
        self.event_consumer_group = "risk-engine"
        self.alert_consumer_group = "alerting"
        
    def ensure_consumer_groups(self):
        """Create consumer groups if they don't exist."""
        try:
            self.redis.xgroup_create(
                self.event_stream,
                self.event_consumer_group,
                id="$",  # Start from new messages
                mkstream=True
            )
            logger.info(f"Created consumer group {self.event_consumer_group}")
        except ResponseError as e:
            if "BUSYGROUP" not in str(e):
                logger.error(f"Error creating consumer group: {e}")
        
        try:
            self.redis.xgroup_create(
                self.alert_stream,
                self.alert_consumer_group,
                id="$",
                mkstream=True
            )
            logger.info(f"Created consumer group {self.alert_consumer_group}")
        except ResponseError as e:
            if "BUSYGROUP" not in str(e):
                logger.error(f"Error creating alert consumer group: {e}")
    
    def add_event(self, event_data: Dict[str, Any], stream: str = None) -> str:
        """
        Add an event to a Redis Stream.
        Returns the stream ID (e.g., "1526919030474-0").
        """
        stream = stream or self.event_stream
        
        try:
            event_id = self.redis.xadd(
                stream,
                event_data,
                maxlen=100000  # Keep last 100k events
            )
            logger.debug(f"Added event to {stream}: {event_id}")
            return event_id
        except Exception as e:
            logger.error(f"Error adding event to stream: {e}")
            raise
    
    def read_events(
        self,
        consumer_name: str,
        stream: str = None,
        count: int = 10,
        block_ms: int = 1000
    ) -> List[tuple]:
        """
        Read events from a stream as a consumer group.
        Returns list of (event_id, event_data) tuples.
        """
        stream = stream or self.event_stream
        group = self.event_consumer_group if stream == self.event_stream else self.alert_consumer_group
        
        try:
            events = self.redis.xreadgroup(
                groupname=group,
                consumername=consumer_name,
                streams={stream: ">"},  # Only new messages
                count=count,
                block=block_ms
            )
            
            result = []
            if events:
                # xreadgroup returns [(stream_name, [(id, data), ...]), ...]
                for stream_name, messages in events:
                    for event_id, event_data in messages:
                        result.append((event_id, event_data))
            
            return result
        except Exception as e:
            logger.error(f"Error reading from stream: {e}")
            return []
    
    def ack_event(self, event_id: str, stream: str = None, group: str = None):
        """Acknowledge that an event was processed."""
        stream = stream or self.event_stream
        group = group or self.event_consumer_group
        
        try:
            self.redis.xack(stream, group, event_id)
            logger.debug(f"Acknowledged event {event_id}")
        except Exception as e:
            logger.error(f"Error acknowledging event: {e}")
    
    def nack_event(self, event_id: str, stream: str = None):
        """Return an event to the stream (nack)."""
        # Redis Streams doesn't have native nack, so we delete from pending and re-add
        stream = stream or self.event_stream
        try:
            # Claim the message to reset it
            self.redis.xclaim(stream, self.event_consumer_group, "retry-consumer", min_idle_time=0)
        except Exception as e:
            logger.error(f"Error nacking event: {e}")
    
    def get_pending_events(self, stream: str = None, group: str = None):
        """Get list of pending (unacked) events."""
        stream = stream or self.event_stream
        group = group or self.event_consumer_group
        
        try:
            pending = self.redis.xpending(stream, group)
            return pending
        except Exception as e:
            logger.error(f"Error getting pending events: {e}")
            return {}
    
    def get_consumer_info(self, stream: str = None, group: str = None):
        """Get consumer group info for monitoring."""
        stream = stream or self.event_stream
        group = group or self.event_consumer_group
        
        try:
            info = self.redis.xinfo_groups(stream)
            return info
        except Exception as e:
            logger.error(f"Error getting consumer info: {e}")
            return []
    
    def set_velocity_counter(self, key: str, value: int, expiry_seconds: int = 3600) -> int:
        """
        Set a velocity counter with automatic expiry.
        Used for login attempts, transaction counts, etc.
        """
        try:
            self.redis.set(key, value, ex=expiry_seconds)
            return value
        except Exception as e:
            logger.error(f"Error setting velocity counter: {e}")
            raise
    
    def increment_velocity_counter(self, key: str, expiry_seconds: int = 3600) -> int:
        """Increment a velocity counter (for rate limiting checks)."""
        try:
            if not self.redis.exists(key):
                self.redis.set(key, 0, ex=expiry_seconds)
            value = self.redis.incr(key)
            return value
        except Exception as e:
            logger.error(f"Error incrementing velocity counter: {e}")
            raise
    
    def get_velocity_counter(self, key: str) -> Optional[int]:
        """Get current velocity counter value."""
        try:
            value = self.redis.get(key)
            return int(value) if value else 0
        except Exception as e:
            logger.error(f"Error getting velocity counter: {e}")
            return None
    
    def cache_user_location(self, user_id: str, lat: float, lon: float, expiry_seconds: int = 86400):
        """Cache user's last known location for velocity checks."""
        try:
            key = f"user:{user_id}:location"
            self.redis.set(key, json.dumps({"lat": lat, "lon": lon}), ex=expiry_seconds)
        except Exception as e:
            logger.error(f"Error caching user location: {e}")
    
    def get_user_location(self, user_id: str) -> Optional[Dict]:
        """Get user's last known location."""
        try:
            key = f"user:{user_id}:location"
            data = self.redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Error getting user location: {e}")
            return None
    
    def cache_device_fingerprint(self, user_id: str, fingerprint_hash: str, expiry_seconds: int = 2592000):  # 30 days
        """Cache user's known device fingerprints."""
        try:
            key = f"user:{user_id}:devices"
            self.redis.sadd(key, fingerprint_hash)
            self.redis.expire(key, expiry_seconds)
        except Exception as e:
            logger.error(f"Error caching device fingerprint: {e}")
    
    def get_known_devices(self, user_id: str) -> set:
        """Get user's known device fingerprints."""
        try:
            key = f"user:{user_id}:devices"
            return self.redis.smembers(key)
        except Exception as e:
            logger.error(f"Error getting known devices: {e}")
            return set()
    
    def is_known_device(self, user_id: str, fingerprint_hash: str) -> bool:
        """Check if device is in user's known devices."""
        try:
            key = f"user:{user_id}:devices"
            return self.redis.sismember(key, fingerprint_hash)
        except Exception as e:
            logger.error(f"Error checking known device: {e}")
            return False
    
    def health_check(self) -> bool:
        """Check Redis connectivity."""
        try:
            return self.redis.ping()
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False


# Singleton instance
_redis_stream_manager: Optional[RedisStreamManager] = None


def get_redis_stream_manager() -> RedisStreamManager:
    """Get or create Redis Stream manager instance."""
    global _redis_stream_manager
    if _redis_stream_manager is None:
        _redis_stream_manager = RedisStreamManager()
        _redis_stream_manager.ensure_consumer_groups()
    return _redis_stream_manager
