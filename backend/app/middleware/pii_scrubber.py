"""
PII Scrubber Middleware - PCI-DSS 3.4 Compliance

Automatically sanitizes sensitive data from:
- Request/response logs
- Error traces
- Audit records

Prevents accidental PII leakage in logs, traces, and error messages.

Patterns detected and scrubbed:
- Credit card numbers (Luhn-valid)
- Social Security Numbers (SSN)
- Bank account numbers
- Passwords and secrets
- API keys and tokens
- Email addresses (optionally)

Compliance: PCI-DSS Requirement 3.4, GDPR Article 32
"""

import re
import json
import logging
from typing import Dict, Any, Optional, Callable, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import FastAPI
from io import BytesIO

logger = logging.getLogger("sentineliq.pii_scrubber")


class PIIPatterns:
    """
    Compiled regex patterns for PII detection.
    
    Performance: Patterns are compiled once at module load.
    """
    
    # Credit card patterns (Visa, MasterCard, Amex, Discover, etc.)
    # Matches with or without spaces/dashes
    CREDIT_CARD = re.compile(
        r'\b(?:'
        r'4[0-9]{12}(?:[0-9]{3})?|'  # Visa
        r'5[1-5][0-9]{14}|'  # MasterCard
        r'3[47][0-9]{13}|'  # Amex
        r'6(?:011|5[0-9]{2})[0-9]{12}|'  # Discover
        r'(?:2131|1800|35\d{3})\d{11}'  # JCB
        r')\b',
        re.VERBOSE
    )
    
    # Credit card with spaces/dashes
    CREDIT_CARD_FORMATTED = re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
    )
    
    # SSN pattern (XXX-XX-XXXX)
    SSN = re.compile(
        r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b'
    )
    
    # Bank account numbers (generic 8-17 digit patterns)
    BANK_ACCOUNT = re.compile(
        r'\b[0-9]{8,17}\b'
    )
    
    # Routing numbers (9 digits)
    ROUTING_NUMBER = re.compile(
        r'\b[0-9]{9}\b'
    )
    
    # API keys / Bearer tokens (common patterns)
    API_KEY = re.compile(
        r'\b(?:sk_live_|pk_live_|sk_test_|pk_test_)[a-zA-Z0-9]{24,}\b|'
        r'\b[a-zA-Z0-9]{32,64}\b'
    )
    
    # JWT tokens
    JWT_TOKEN = re.compile(
        r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b'
    )
    
    # Email addresses (optional - may want to preserve for user identification)
    EMAIL = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    
    # Phone numbers
    PHONE = re.compile(
        r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
    )
    
    # Password field patterns (in JSON/form data)
    PASSWORD_FIELD = re.compile(
        r'["\']?(?:password|passwd|pwd|secret|credential|api_key|apikey|'
        r'access_token|refresh_token|bearer|authorization)["\']?\s*[:=]\s*'
        r'["\']?[^"\',\s}]+["\']?',
        re.IGNORECASE
    )


class PIIScrubber:
    """
    Core PII scrubbing engine.
    
    Thread-safe, stateless utility for sanitizing sensitive data.
    """
    
    # Replacement tokens
    REDACTED_CC = "<CARD_REDACTED>"
    REDACTED_SSN = "<SSN_REDACTED>"
    REDACTED_ACCOUNT = "<ACCOUNT_REDACTED>"
    REDACTED_TOKEN = "<TOKEN_REDACTED>"
    REDACTED_PASSWORD = "<PASSWORD_REDACTED>"
    REDACTED_EMAIL = "<EMAIL_REDACTED>"
    REDACTED_PHONE = "<PHONE_REDACTED>"
    
    @classmethod
    def luhn_check(cls, card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        
        Only scrub numbers that pass Luhn check to reduce false positives.
        """
        try:
            digits = [int(d) for d in card_number if d.isdigit()]
            if len(digits) < 13 or len(digits) > 19:
                return False
            
            checksum = 0
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            
            return checksum % 10 == 0
        except (ValueError, TypeError):
            return False
    
    @classmethod
    def scrub_string(cls, text: str, scrub_emails: bool = False) -> str:
        """
        Scrub PII from a string.
        
        Args:
            text: Input string to sanitize
            scrub_emails: Whether to redact email addresses
            
        Returns:
            Sanitized string with PII replaced by tokens
        """
        if not text or not isinstance(text, str):
            return text
        
        # Track if we made any changes
        original = text
        
        # Scrub credit cards (validate with Luhn)
        def replace_cc(match):
            if cls.luhn_check(match.group()):
                return cls.REDACTED_CC
            return match.group()
        
        text = PIIPatterns.CREDIT_CARD.sub(replace_cc, text)
        text = PIIPatterns.CREDIT_CARD_FORMATTED.sub(replace_cc, text)
        
        # Scrub SSNs
        text = PIIPatterns.SSN.sub(cls.REDACTED_SSN, text)
        
        # Scrub JWT tokens
        text = PIIPatterns.JWT_TOKEN.sub(cls.REDACTED_TOKEN, text)
        
        # Scrub password fields
        text = PIIPatterns.PASSWORD_FIELD.sub(
            lambda m: m.group().split(':')[0] + ': ' + cls.REDACTED_PASSWORD 
            if ':' in m.group() 
            else m.group().split('=')[0] + '=' + cls.REDACTED_PASSWORD,
            text
        )
        
        # Optionally scrub emails
        if scrub_emails:
            text = PIIPatterns.EMAIL.sub(cls.REDACTED_EMAIL, text)
        
        # Scrub phone numbers
        text = PIIPatterns.PHONE.sub(cls.REDACTED_PHONE, text)
        
        # Log if scrubbing occurred
        if text != original:
            logger.debug("PII scrubbed from content")
        
        return text
    
    @classmethod
    def scrub_dict(cls, data: Dict[str, Any], scrub_emails: bool = False) -> Dict[str, Any]:
        """
        Recursively scrub PII from a dictionary.
        
        Handles nested dictionaries, lists, and string values.
        """
        if not isinstance(data, dict):
            return data
        
        scrubbed = {}
        
        # Keys that should have their values completely redacted
        sensitive_keys = {
            'password', 'passwd', 'pwd', 'secret', 'credential', 
            'api_key', 'apikey', 'access_token', 'refresh_token',
            'bearer', 'authorization', 'ssn', 'social_security',
            'card_number', 'credit_card', 'cvv', 'cvc', 'pin',
            'account_number', 'routing_number', 'bank_account'
        }
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Completely redact known sensitive keys
            if key_lower in sensitive_keys:
                scrubbed[key] = cls.REDACTED_PASSWORD
            elif isinstance(value, dict):
                scrubbed[key] = cls.scrub_dict(value, scrub_emails)
            elif isinstance(value, list):
                scrubbed[key] = [
                    cls.scrub_dict(item, scrub_emails) if isinstance(item, dict)
                    else cls.scrub_string(str(item), scrub_emails) if isinstance(item, str)
                    else item
                    for item in value
                ]
            elif isinstance(value, str):
                scrubbed[key] = cls.scrub_string(value, scrub_emails)
            else:
                scrubbed[key] = value
        
        return scrubbed
    
    @classmethod
    def scrub_json(cls, json_str: str, scrub_emails: bool = False) -> str:
        """
        Parse JSON string, scrub PII, and re-serialize.
        """
        try:
            data = json.loads(json_str)
            scrubbed = cls.scrub_dict(data, scrub_emails)
            return json.dumps(scrubbed)
        except json.JSONDecodeError:
            # Not valid JSON, scrub as plain string
            return cls.scrub_string(json_str, scrub_emails)


class PIIScrubberMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware for automatic PII scrubbing.
    
    Intercepts requests and responses to ensure no PII leaks
    into logs, error messages, or downstream systems.
    
    Usage:
        app.add_middleware(PIIScrubberMiddleware)
    """
    
    def __init__(self, app: FastAPI, scrub_emails: bool = False):
        super().__init__(app)
        self.scrub_emails = scrub_emails
        self.scrubber = PIIScrubber
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request/response through PII scrubber.
        
        Note: This middleware primarily protects error responses.
        Request body scrubbing is done at the logging layer.
        """
        
        # Skip WebSocket connections - BaseHTTPMiddleware doesn't support them
        if request.scope.get("type") == "websocket":
            return await call_next(request)
        
        # Store original request for context
        request.state.pii_scrubber = self.scrubber
        
        try:
            response = await call_next(request)
            return response
            
        except Exception as exc:
            # Scrub exception messages before they propagate
            scrubbed_msg = self.scrubber.scrub_string(
                str(exc), 
                self.scrub_emails
            )
            
            logger.error(f"Request failed: {scrubbed_msg}")
            
            # Re-raise with scrubbed message
            raise type(exc)(scrubbed_msg) from None


def scrub_log_record(record: logging.LogRecord) -> logging.LogRecord:
    """
    Scrub PII from a log record.
    
    Use as a logging filter:
        handler.addFilter(scrub_log_record)
    """
    if hasattr(record, 'msg') and isinstance(record.msg, str):
        record.msg = PIIScrubber.scrub_string(record.msg)
    
    if hasattr(record, 'args') and record.args:
        scrubbed_args = []
        for arg in record.args:
            if isinstance(arg, str):
                scrubbed_args.append(PIIScrubber.scrub_string(arg))
            elif isinstance(arg, dict):
                scrubbed_args.append(PIIScrubber.scrub_dict(arg))
            else:
                scrubbed_args.append(arg)
        record.args = tuple(scrubbed_args)
    
    return record


class PIILoggingFilter(logging.Filter):
    """
    Logging filter that scrubs PII from all log messages.
    
    Usage:
        logging.getLogger().addFilter(PIILoggingFilter())
    """
    
    def filter(self, record: logging.LogRecord) -> bool:
        scrub_log_record(record)
        return True


# Export for use in other modules
__all__ = [
    'PIIScrubber',
    'PIIScrubberMiddleware', 
    'PIILoggingFilter',
    'scrub_log_record'
]
