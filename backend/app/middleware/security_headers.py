"""
Security Headers Middleware (MILESTONE 6 - STEP 6)

Adds OWASP-recommended security headers to all responses.
Prevents common attacks: clickjacking, MIME sniffing, XSS, etc.
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all HTTP responses."""
    
    async def dispatch(self, request: Request, call_next):
        # Skip WebSocket connections - BaseHTTPMiddleware doesn't support them
        if request.scope.get("type") == "websocket":
            return await call_next(request)
        
        response = await call_next(request)
        
        # Prevent MIME sniffing (OWASP A06:2021 - Vulnerable Components)
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking (OWASP A05:2021 - Broken Access Control)
        response.headers["X-Frame-Options"] = "DENY"
        
        # Enable XSS protection in older browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Restrict browser features (geolocation, microphone, camera)
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response
