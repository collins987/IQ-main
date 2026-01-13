"""
Token Bucket Rate Limiter Middleware

Implements the Token Bucket algorithm for rate limiting with:
- Per-tenant rate limits
- Per-IP rate limits
- Burst traffic handling
- Graceful degradation

Algorithm:
- Bucket holds tokens up to MAX_TOKENS
- Tokens are added at REFILL_RATE per second
- Each request consumes 1 token
- If no tokens available, request is rejected (429)

Advantages over simple counters:
- Allows burst traffic up to bucket size
- Smooth rate limiting over time
- More fair to legitimate users

Compliance: OWASP API Security Top 10 - API4:2019
"""

import time
import logging
from typing import Optional, Dict, Tuple
from dataclasses import dataclass, field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from fastapi import FastAPI
import redis
import json

from app.config import REDIS_URL

logger = logging.getLogger("sentineliq.rate_limiter")


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    
    # Default limits
    requests_per_second: float = 10.0  # Refill rate
    burst_size: int = 50  # Max tokens (bucket capacity)
    
    # Per-endpoint overrides
    endpoint_limits: Dict[str, Tuple[float, int]] = field(default_factory=dict)
    
    # Exempt paths (no rate limiting)
    exempt_paths: list = field(default_factory=lambda: [
        "/health",
        "/health/detailed",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc"
    ])
    
    # Stricter limits for sensitive endpoints
    sensitive_endpoints: Dict[str, Tuple[float, int]] = field(default_factory=lambda: {
        "/auth/login": (1.0, 5),  # 1 req/sec, burst of 5
        "/auth/register": (0.5, 3),  # 0.5 req/sec, burst of 3
        "/users/password/reset": (0.2, 2),  # 0.2 req/sec, burst of 2
    })


class TokenBucket:
    """
    In-memory token bucket implementation.
    
    For single-instance deployments or testing.
    Production should use RedisTokenBucket.
    """
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # tokens per second
        self.capacity = capacity  # max tokens
        self.tokens = capacity  # current tokens
        self.last_update = time.time()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from the bucket.
        
        Returns True if successful, False if rate limited.
        """
        now = time.time()
        elapsed = now - self.last_update
        
        # Refill tokens based on elapsed time
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate
        )
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        return False
    
    def get_retry_after(self) -> float:
        """Calculate seconds until a token is available."""
        if self.tokens >= 1:
            return 0
        return (1 - self.tokens) / self.rate


class RedisTokenBucket:
    """
    Distributed token bucket using Redis.
    
    Uses Redis for state storage to support:
    - Multi-instance deployments
    - Shared rate limits across pods
    - Persistence across restarts
    
    Implementation uses Lua scripts for atomicity.
    """
    
    # Lua script for atomic token bucket operation
    CONSUME_SCRIPT = """
    local key = KEYS[1]
    local rate = tonumber(ARGV[1])
    local capacity = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local requested = tonumber(ARGV[4])
    
    -- Get current bucket state
    local bucket = redis.call('HMGET', key, 'tokens', 'last_update')
    local tokens = tonumber(bucket[1]) or capacity
    local last_update = tonumber(bucket[2]) or now
    
    -- Calculate token refill
    local elapsed = now - last_update
    tokens = math.min(capacity, tokens + elapsed * rate)
    
    -- Attempt to consume
    local allowed = 0
    local remaining = tokens
    
    if tokens >= requested then
        tokens = tokens - requested
        allowed = 1
        remaining = tokens
    end
    
    -- Update bucket state with TTL (bucket expires after 2x capacity/rate seconds)
    local ttl = math.ceil(capacity / rate * 2)
    redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
    redis.call('EXPIRE', key, ttl)
    
    -- Return: allowed (0/1), remaining tokens, retry_after seconds
    local retry_after = 0
    if allowed == 0 then
        retry_after = (requested - tokens) / rate
    end
    
    return {allowed, remaining, retry_after}
    """
    
    def __init__(self, redis_client: redis.Redis, key_prefix: str = "ratelimit"):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self._script = None
    
    @property
    def script(self):
        """Lazy-load the Lua script."""
        if self._script is None:
            self._script = self.redis.register_script(self.CONSUME_SCRIPT)
        return self._script
    
    def _get_key(self, identifier: str) -> str:
        """Generate Redis key for bucket."""
        return f"{self.key_prefix}:{identifier}"
    
    def consume(
        self, 
        identifier: str, 
        rate: float, 
        capacity: int, 
        tokens: int = 1
    ) -> Tuple[bool, float, float]:
        """
        Attempt to consume tokens from a bucket.
        
        Args:
            identifier: Unique identifier (IP, user_id, tenant)
            rate: Refill rate (tokens per second)
            capacity: Bucket capacity (max tokens)
            tokens: Number of tokens to consume
            
        Returns:
            Tuple of (allowed, remaining, retry_after)
        """
        key = self._get_key(identifier)
        now = time.time()
        
        try:
            result = self.script(
                keys=[key],
                args=[rate, capacity, now, tokens]
            )
            
            allowed = bool(result[0])
            remaining = float(result[1])
            retry_after = float(result[2])
            
            return allowed, remaining, retry_after
            
        except redis.RedisError as e:
            logger.error(f"Redis error in rate limiter: {e}")
            # Fail open - allow request if Redis is down
            return True, 0, 0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware for token bucket rate limiting.
    
    Features:
    - Per-IP rate limiting
    - Per-user rate limiting (if authenticated)
    - Per-endpoint custom limits
    - Burst traffic handling
    - Proper 429 responses with Retry-After header
    - Graceful degradation if Redis unavailable
    
    Usage:
        app.add_middleware(RateLimitMiddleware)
    """
    
    def __init__(
        self, 
        app: FastAPI, 
        config: Optional[RateLimitConfig] = None,
        redis_url: str = REDIS_URL
    ):
        super().__init__(app)
        self.config = config or RateLimitConfig()
        
        # Initialize Redis connection with graceful degradation
        self.use_redis = False
        self.redis = None
        self.bucket = None
        self.buckets: Dict[str, TokenBucket] = {}
        
        try:
            self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
            self.redis.ping()  # Test connection
            self.bucket = RedisTokenBucket(self.redis)
            self.use_redis = True
            logger.info("Rate limiter using Redis backend")
        except redis.ConnectionError as e:
            logger.warning(f"Redis not available for rate limiter, using in-memory fallback: {e}")
            self.use_redis = False
        except Exception as e:
            logger.warning(f"Redis initialization failed, using in-memory rate limiter: {e}")
            self.use_redis = False
    
    def _get_identifier(self, request: Request) -> str:
        """
        Get unique identifier for rate limiting.
        
        Priority:
        1. Authenticated user ID
        2. API key / tenant ID
        3. Client IP address
        """
        # Check for authenticated user
        if hasattr(request.state, 'user') and request.state.user:
            return f"user:{request.state.user.id}"
        
        # Check for API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"apikey:{api_key[:16]}"  # Use first 16 chars
        
        # Fall back to IP
        client_ip = self._get_client_ip(request)
        return f"ip:{client_ip}"
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP, considering proxies."""
        # Check X-Forwarded-For header
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # First IP in the list is the client
            return forwarded.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to direct connection
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _get_limits(self, path: str) -> Tuple[float, int]:
        """Get rate limits for a path."""
        # Check sensitive endpoints first
        for endpoint, limits in self.config.sensitive_endpoints.items():
            if path.startswith(endpoint):
                return limits
        
        # Check custom endpoint limits
        if path in self.config.endpoint_limits:
            return self.config.endpoint_limits[path]
        
        # Return default limits
        return self.config.requests_per_second, self.config.burst_size
    
    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from rate limiting."""
        return any(path.startswith(exempt) for exempt in self.config.exempt_paths)
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request through rate limiter."""
        
        # Skip WebSocket connections - BaseHTTPMiddleware doesn't support them
        if request.scope.get("type") == "websocket":
            return await call_next(request)
        
        path = request.url.path
        
        # Skip exempt paths
        if self._is_exempt(path):
            return await call_next(request)
        
        identifier = self._get_identifier(request)
        rate, capacity = self._get_limits(path)
        
        # Consume token
        if self.use_redis:
            allowed, remaining, retry_after = self.bucket.consume(
                identifier, rate, capacity
            )
        else:
            # In-memory fallback
            if identifier not in self.buckets:
                self.buckets[identifier] = TokenBucket(rate, capacity)
            
            bucket = self.buckets[identifier]
            allowed = bucket.consume()
            remaining = bucket.tokens
            retry_after = bucket.get_retry_after() if not allowed else 0
        
        # Add rate limit headers to response
        response = None
        
        if not allowed:
            # Rate limited
            logger.warning(
                f"Rate limit exceeded for {identifier} on {path}",
                extra={
                    "identifier": identifier,
                    "path": path,
                    "retry_after": retry_after
                }
            )
            
            response = JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": round(retry_after, 1)
                },
                headers={
                    "Retry-After": str(int(retry_after) + 1),
                    "X-RateLimit-Limit": str(capacity),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time() + retry_after))
                }
            )
        else:
            # Process request
            response = await call_next(request)
            
            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(capacity)
            response.headers["X-RateLimit-Remaining"] = str(int(remaining))
            response.headers["X-RateLimit-Reset"] = str(
                int(time.time() + (capacity - remaining) / rate)
            )
        
        return response


# Convenience function for testing
def create_rate_limiter(app: FastAPI, config: Optional[RateLimitConfig] = None):
    """Create and configure rate limiter middleware."""
    app.add_middleware(RateLimitMiddleware, config=config)


__all__ = [
    'RateLimitMiddleware',
    'RateLimitConfig',
    'TokenBucket',
    'RedisTokenBucket',
    'create_rate_limiter'
]
