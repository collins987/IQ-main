# app/core/middleware.py
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime, timedelta
from collections import defaultdict
from app.config import MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW_MINUTES

# In-memory rate limiter (for development/testing)
# For production, use Redis
login_attempts = defaultdict(list)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # This is optional - the rate limiting is already handled in auth_utils
        response = await call_next(request)
        return response
