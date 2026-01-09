"""
Milestone 8: Request/Response Logging Middleware
Tracks all incoming requests and outgoing responses
"""

import time
import uuid
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from app.core.logging import logger, log_api_event
from app.core.metrics import MetricsTracker
import re


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging all HTTP requests and responses
    Tracks timing, user info, and status codes
    """
    
    # Routes to exclude from detailed logging (health checks, metrics, etc)
    EXCLUDE_PATHS = [
        "/health",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc"
    ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Extract client IP
        client_ip = self._get_client_ip(request)
        request.state.ip_address = client_ip
        
        # Skip detailed logging for excluded paths
        if self._should_skip_logging(request.url.path):
            response = await call_next(request)
            return response
        
        # Start timer
        start_time = time.time()
        
        # Log incoming request
        extra_data = {
            "request_id": request_id,
            "ip_address": client_ip,
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
        }
        
        logger.info(
            f"Incoming request: {request.method} {request.url.path}",
            extra=extra_data
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            duration_ms = duration * 1000
            
            # Extract user ID if available
            user_id = None
            if hasattr(request.state, "user_id"):
                user_id = request.state.user_id
            
            # Normalize endpoint for metrics (remove IDs, etc)
            endpoint = self._normalize_endpoint(request.url.path)
            
            # Track metrics
            MetricsTracker.track_api_request(
                method=request.method,
                endpoint=endpoint,
                status_code=response.status_code,
                duration=duration
            )
            
            # Log response
            log_api_event(
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
                user_id=user_id,
                ip_address=client_ip
            )
            
            return response
        
        except Exception as exc:
            # Calculate duration
            duration = time.time() - start_time
            
            # Extract user ID if available
            user_id = None
            if hasattr(request.state, "user_id"):
                user_id = request.state.user_id
            
            # Normalize endpoint for metrics
            endpoint = self._normalize_endpoint(request.url.path)
            
            # Track error metric
            MetricsTracker.track_api_error(
                method=request.method,
                endpoint=endpoint,
                error_type=type(exc).__name__
            )
            
            # Log error
            error_data = {
                "request_id": request_id,
                "ip_address": client_ip,
                "method": request.method,
                "path": request.url.path,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            }
            
            logger.error(
                f"Request error: {request.method} {request.url.path}",
                extra=error_data,
                exc_info=exc
            )
            
            raise
    
    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP from request"""
        # Check X-Forwarded-For header first (for proxies)
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        
        # Fall back to client address
        if request.client:
            return request.client.host
        
        return "unknown"
    
    @staticmethod
    def _should_skip_logging(path: str) -> bool:
        """Check if path should be excluded from detailed logging"""
        return any(path.startswith(excluded) for excluded in RequestLoggingMiddleware.EXCLUDE_PATHS)
    
    @staticmethod
    def _normalize_endpoint(path: str) -> str:
        """
        Normalize path for metrics
        Converts /users/123/profile to /users/{id}/profile
        """
        # Replace UUIDs and numeric IDs with placeholder
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '{id}', path, flags=re.IGNORECASE)
        normalized = re.sub(r'/\d+', '/{id}', normalized)
        return normalized


class UserTrackingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for tracking authenticated user info
    Adds user ID to request state
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Try to extract user ID from token
        auth_header = request.headers.get("authorization", "")
        
        if auth_header.startswith("Bearer "):
            # User token is present - mark as authenticated
            # The actual user extraction happens in dependencies.py
            request.state.authenticated = True
        
        response = await call_next(request)
        return response
