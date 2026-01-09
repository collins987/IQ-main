"""
Idempotency Service - Exactly-Once Event Processing

Prevents duplicate processing of events during retries, network issues,
or message redelivery. Critical for financial systems where duplicate
processing could result in double charges or incorrect balances.

Implementation:
- Redis-based idempotency key storage
- Configurable TTL per event type
- Atomic check-and-set operations
- Graceful degradation if Redis unavailable

Compliance: Financial-grade exactly-once semantics
"""

import logging
import json
import hashlib
from typing import Optional, Dict, Any, Callable, TypeVar, Union
from datetime import datetime, timedelta
from functools import wraps
from dataclasses import dataclass
from enum import Enum
import redis
from redis.exceptions import RedisError

from app.config import REDIS_URL

logger = logging.getLogger("sentineliq.idempotency")

T = TypeVar('T')


class IdempotencyStatus(Enum):
    """Status of idempotency check."""
    NEW = "new"  # First time seeing this key
    DUPLICATE = "duplicate"  # Key already processed
    IN_PROGRESS = "in_progress"  # Key currently being processed
    FAILED = "failed"  # Previous processing failed


@dataclass
class IdempotencyResult:
    """Result of an idempotency check."""
    status: IdempotencyStatus
    key: str
    cached_response: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class IdempotencyConfig:
    """Configuration for idempotency service."""
    
    # Default TTL for idempotency keys (24 hours)
    DEFAULT_TTL_SECONDS = 86400
    
    # TTL by event type (in seconds)
    EVENT_TYPE_TTLS = {
        "transaction.attempted": 604800,  # 7 days for transactions
        "transaction.completed": 604800,
        "authentication.login": 3600,  # 1 hour for logins
        "authentication.failed": 3600,
        "risk_decision": 86400,  # 24 hours for risk decisions
        "alert.generated": 86400,
    }
    
    # Key prefix in Redis
    KEY_PREFIX = "idempotency"
    
    # Lock prefix for in-progress operations
    LOCK_PREFIX = "idempotency_lock"
    
    # Lock timeout (max time an operation can be "in progress")
    LOCK_TIMEOUT_SECONDS = 30


class IdempotencyService:
    """
    Service for ensuring exactly-once processing of events.
    
    Usage:
        idempotency = IdempotencyService()
        
        # Check before processing
        result = idempotency.check("event_123")
        if result.status == IdempotencyStatus.DUPLICATE:
            return result.cached_response
        
        # Process event...
        
        # Mark as complete
        idempotency.complete("event_123", response_data)
    """
    
    def __init__(self, redis_url: str = REDIS_URL):
        self.config = IdempotencyConfig()
        
        try:
            self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
            self.redis.ping()
            self._available = True
            logger.info("Idempotency service connected to Redis")
        except RedisError as e:
            logger.warning(f"Redis not available for idempotency: {e}")
            self._available = False
            self.redis = None
    
    @property
    def is_available(self) -> bool:
        """Check if idempotency service is available."""
        return self._available
    
    def _get_key(self, idempotency_key: str) -> str:
        """Generate Redis key."""
        return f"{self.config.KEY_PREFIX}:{idempotency_key}"
    
    def _get_lock_key(self, idempotency_key: str) -> str:
        """Generate Redis lock key."""
        return f"{self.config.LOCK_PREFIX}:{idempotency_key}"
    
    def _get_ttl(self, event_type: Optional[str] = None) -> int:
        """Get TTL for an event type."""
        if event_type and event_type in self.config.EVENT_TYPE_TTLS:
            return self.config.EVENT_TYPE_TTLS[event_type]
        return self.config.DEFAULT_TTL_SECONDS
    
    def generate_key(
        self,
        event_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate a deterministic idempotency key.
        
        Can be based on:
        - Explicit event_id
        - Combination of user_id + action + payload hash
        """
        if event_id:
            return event_id
        
        # Generate from components
        components = []
        if user_id:
            components.append(f"user:{user_id}")
        if action:
            components.append(f"action:{action}")
        if payload:
            payload_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()
            ).hexdigest()[:16]
            components.append(f"payload:{payload_hash}")
        
        if not components:
            raise ValueError("Must provide event_id or user_id+action+payload")
        
        return ":".join(components)
    
    def check(
        self,
        idempotency_key: str,
        event_type: Optional[str] = None
    ) -> IdempotencyResult:
        """
        Check if an event has already been processed.
        
        Returns:
            IdempotencyResult with status and cached response if available
        """
        if not self._available:
            # Fail open - allow processing if Redis unavailable
            logger.warning("Idempotency check skipped - Redis unavailable")
            return IdempotencyResult(
                status=IdempotencyStatus.NEW,
                key=idempotency_key
            )
        
        key = self._get_key(idempotency_key)
        lock_key = self._get_lock_key(idempotency_key)
        
        try:
            # Check for existing record
            existing = self.redis.hgetall(key)
            
            if existing:
                status_str = existing.get("status", "completed")
                
                if status_str == "in_progress":
                    # Check if lock is still valid
                    if self.redis.exists(lock_key):
                        return IdempotencyResult(
                            status=IdempotencyStatus.IN_PROGRESS,
                            key=idempotency_key
                        )
                    # Lock expired, treat as failed
                    return IdempotencyResult(
                        status=IdempotencyStatus.FAILED,
                        key=idempotency_key
                    )
                
                # Already completed
                cached_response = None
                if "response" in existing:
                    try:
                        cached_response = json.loads(existing["response"])
                    except json.JSONDecodeError:
                        pass
                
                return IdempotencyResult(
                    status=IdempotencyStatus.DUPLICATE,
                    key=idempotency_key,
                    cached_response=cached_response,
                    created_at=datetime.fromisoformat(existing.get("created_at", ""))
                    if existing.get("created_at") else None
                )
            
            # New key - acquire lock
            ttl = self._get_ttl(event_type)
            
            # Atomic set-if-not-exists with lock
            pipe = self.redis.pipeline()
            pipe.hsetnx(key, "status", "in_progress")
            pipe.hsetnx(key, "created_at", datetime.utcnow().isoformat())
            pipe.expire(key, ttl)
            pipe.setex(lock_key, self.config.LOCK_TIMEOUT_SECONDS, "1")
            results = pipe.execute()
            
            if results[0]:  # hsetnx returned 1 (key was set)
                return IdempotencyResult(
                    status=IdempotencyStatus.NEW,
                    key=idempotency_key
                )
            else:
                # Race condition - another process got there first
                return IdempotencyResult(
                    status=IdempotencyStatus.IN_PROGRESS,
                    key=idempotency_key
                )
                
        except RedisError as e:
            logger.error(f"Redis error in idempotency check: {e}")
            # Fail open
            return IdempotencyResult(
                status=IdempotencyStatus.NEW,
                key=idempotency_key
            )
    
    def complete(
        self,
        idempotency_key: str,
        response: Optional[Dict[str, Any]] = None,
        event_type: Optional[str] = None
    ) -> bool:
        """
        Mark an event as successfully processed.
        
        Args:
            idempotency_key: The key to mark complete
            response: Response to cache for duplicate requests
            event_type: Event type for TTL calculation
            
        Returns:
            True if marked successfully, False otherwise
        """
        if not self._available:
            return False
        
        key = self._get_key(idempotency_key)
        lock_key = self._get_lock_key(idempotency_key)
        ttl = self._get_ttl(event_type)
        
        try:
            pipe = self.redis.pipeline()
            pipe.hset(key, "status", "completed")
            pipe.hset(key, "completed_at", datetime.utcnow().isoformat())
            
            if response:
                pipe.hset(key, "response", json.dumps(response))
            
            pipe.expire(key, ttl)
            pipe.delete(lock_key)
            pipe.execute()
            
            logger.debug(f"Idempotency key completed: {idempotency_key}")
            return True
            
        except RedisError as e:
            logger.error(f"Redis error completing idempotency key: {e}")
            return False
    
    def fail(
        self,
        idempotency_key: str,
        error: Optional[str] = None
    ) -> bool:
        """
        Mark an event processing as failed.
        
        This allows retry of the operation.
        """
        if not self._available:
            return False
        
        key = self._get_key(idempotency_key)
        lock_key = self._get_lock_key(idempotency_key)
        
        try:
            pipe = self.redis.pipeline()
            pipe.hset(key, "status", "failed")
            pipe.hset(key, "failed_at", datetime.utcnow().isoformat())
            
            if error:
                pipe.hset(key, "error", error)
            
            pipe.delete(lock_key)
            pipe.execute()
            
            logger.debug(f"Idempotency key marked failed: {idempotency_key}")
            return True
            
        except RedisError as e:
            logger.error(f"Redis error failing idempotency key: {e}")
            return False
    
    def delete(self, idempotency_key: str) -> bool:
        """Delete an idempotency key (for testing/cleanup)."""
        if not self._available:
            return False
        
        try:
            key = self._get_key(idempotency_key)
            lock_key = self._get_lock_key(idempotency_key)
            self.redis.delete(key, lock_key)
            return True
        except RedisError:
            return False


def idempotent(
    key_func: Optional[Callable[..., str]] = None,
    event_type: Optional[str] = None
):
    """
    Decorator for making functions idempotent.
    
    Usage:
        @idempotent(key_func=lambda event: event.event_id)
        async def process_event(event: SentinelEvent):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> T:
            service = get_idempotency_service()
            
            # Generate key
            if key_func:
                idempotency_key = key_func(*args, **kwargs)
            elif 'idempotency_key' in kwargs:
                idempotency_key = kwargs['idempotency_key']
            elif args and hasattr(args[0], 'event_id'):
                idempotency_key = args[0].event_id
            else:
                raise ValueError("Cannot determine idempotency key")
            
            # Check idempotency
            result = service.check(idempotency_key, event_type)
            
            if result.status == IdempotencyStatus.DUPLICATE:
                logger.info(f"Duplicate request: {idempotency_key}")
                return result.cached_response
            
            if result.status == IdempotencyStatus.IN_PROGRESS:
                logger.warning(f"Request in progress: {idempotency_key}")
                raise Exception("Request already in progress")
            
            # Process
            try:
                response = await func(*args, **kwargs)
                service.complete(idempotency_key, response, event_type)
                return response
            except Exception as e:
                service.fail(idempotency_key, str(e))
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> T:
            service = get_idempotency_service()
            
            # Generate key
            if key_func:
                idempotency_key = key_func(*args, **kwargs)
            elif 'idempotency_key' in kwargs:
                idempotency_key = kwargs['idempotency_key']
            else:
                raise ValueError("Cannot determine idempotency key")
            
            # Check idempotency
            result = service.check(idempotency_key, event_type)
            
            if result.status == IdempotencyStatus.DUPLICATE:
                return result.cached_response
            
            # Process
            try:
                response = func(*args, **kwargs)
                service.complete(idempotency_key, response, event_type)
                return response
            except Exception as e:
                service.fail(idempotency_key, str(e))
                raise
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


# Singleton instance
_idempotency_service: Optional[IdempotencyService] = None


def get_idempotency_service() -> IdempotencyService:
    """Get or create idempotency service singleton."""
    global _idempotency_service
    if _idempotency_service is None:
        _idempotency_service = IdempotencyService()
    return _idempotency_service


__all__ = [
    'IdempotencyService',
    'IdempotencyResult',
    'IdempotencyStatus',
    'IdempotencyConfig',
    'get_idempotency_service',
    'idempotent'
]
