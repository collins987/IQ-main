"""
Milestone 8: Centralized Logging System
Structured JSON logging for all SentinelIQ events
"""

import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict, Optional
from app.config import LOG_LEVEL


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs logs as JSON for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add custom fields if present
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id
        if hasattr(record, "ip_address"):
            log_data["ip_address"] = record.ip_address
        if hasattr(record, "method"):
            log_data["method"] = record.method
        if hasattr(record, "path"):
            log_data["path"] = record.path
        if hasattr(record, "status_code"):
            log_data["status_code"] = record.status_code
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms
        if hasattr(record, "action"):
            log_data["action"] = record.action
        if hasattr(record, "target"):
            log_data["target"] = record.target
        if hasattr(record, "details"):
            log_data["details"] = record.details
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


def setup_logger(name: str) -> logging.Logger:
    """
    Setup a structured JSON logger
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)
    
    # Remove existing handlers
    if logger.handlers:
        logger.handlers.clear()
    
    # Console handler with JSON formatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter())
    logger.addHandler(console_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


# Initialize main app logger
logger = setup_logger("sentineliq")


class LogContextFilter(logging.Filter):
    """Filter that adds context data to logs"""
    
    def __init__(self):
        super().__init__()
        self.context = {}
    
    def filter(self, record: logging.LogRecord) -> bool:
        # Add context to record
        for key, value in self.context.items():
            setattr(record, key, value)
        return True


def log_event(
    action: str,
    user_id: Optional[str] = None,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    level: str = "INFO"
) -> None:
    """
    Log a structured event
    
    Args:
        action: What action occurred (e.g., "user_login", "forbidden_access")
        user_id: User ID performing the action
        target: What was targeted (e.g., route, resource)
        details: Additional context data
        level: Log level (INFO, WARNING, ERROR)
    """
    extra = {
        "action": action,
        "target": target,
        "details": details or {},
    }
    
    if user_id:
        extra["user_id"] = user_id
    
    log_message = f"{action}"
    if target:
        log_message += f" on {target}"
    
    getattr(logger, level.lower())(log_message, extra=extra)


# Event logging shortcuts
def log_auth_event(
    action: str,
    user_id: Optional[str] = None,
    email: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: bool = True,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Log authentication-related events"""
    extra_details = details or {}
    extra_details.update({
        "email": email,
        "ip_address": ip_address,
        "success": success,
    })
    log_event(
        action=f"auth_{action}",
        user_id=user_id,
        target="authentication",
        details=extra_details,
        level="INFO" if success else "WARNING"
    )


def log_access_event(
    action: str,
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    allowed: bool = True,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Log access control events"""
    extra_details = details or {}
    extra_details["allowed"] = allowed
    log_event(
        action=f"access_{action}",
        user_id=user_id,
        target=resource,
        details=extra_details,
        level="INFO" if allowed else "WARNING"
    )


def log_api_event(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    error: Optional[str] = None
) -> None:
    """Log API request/response events"""
    details = {
        "method": method,
        "path": path,
        "status_code": status_code,
        "duration_ms": duration_ms,
    }
    if error:
        details["error"] = error
    
    level = "INFO" if status_code < 400 else "WARNING" if status_code < 500 else "ERROR"
    
    log_event(
        action="api_request",
        user_id=user_id,
        target=f"{method} {path}",
        details=details,
        level=level
    )
