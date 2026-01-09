"""
Secure Message Center - Notification Hub with PII Protection

Implements the "Secure Message Center Pattern":
- Public notifications contain NO sensitive data
- Sensitive details only accessible via authenticated portal
- Sanitized alerts for email/SMS/push channels
- Audit trail for all message access

Compliance:
- PCI-DSS: No cardholder data in notifications
- GDPR: Right to access notification history
- SOC 2: Complete audit trail

Reference: Gap Analysis - Secure Message Center Pattern (HIGH priority)
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from uuid import uuid4
import hashlib

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel, Field

from app.dependencies import get_current_user
from app.models import User
from app.core.logging import log_event

logger = logging.getLogger("sentineliq.message_center")

router = APIRouter(prefix="/api/v1/messages", tags=["messages"])


class MessageChannel(str, Enum):
    """Delivery channels for messages."""
    PORTAL = "portal"  # In-app only (full details)
    EMAIL = "email"  # Sanitized summary
    SMS = "sms"  # Minimal info
    PUSH = "push"  # Mobile push notification
    WEBHOOK = "webhook"  # External system


class MessagePriority(str, Enum):
    """Message priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MessageCategory(str, Enum):
    """Message categories."""
    SECURITY_ALERT = "security_alert"
    FRAUD_ALERT = "fraud_alert"
    TRANSACTION = "transaction"
    ACCOUNT = "account"
    SYSTEM = "system"
    COMPLIANCE = "compliance"


@dataclass
class SecureMessage:
    """
    A secure message with separated public and sensitive content.
    """
    id: str
    user_id: str
    org_id: str
    
    # Metadata (safe for any channel)
    category: MessageCategory
    priority: MessagePriority
    created_at: datetime
    
    # Public content (sanitized for external channels)
    public_title: str
    public_summary: str  # No PII/sensitive data
    
    # Sensitive content (portal only)
    sensitive_title: str
    sensitive_body: str
    sensitive_details: Dict[str, Any] = field(default_factory=dict)
    
    # Delivery tracking
    channels_delivered: List[MessageChannel] = field(default_factory=list)
    portal_viewed: bool = False
    portal_viewed_at: Optional[datetime] = None
    
    # Access control
    requires_mfa: bool = False
    access_token: str = field(default_factory=lambda: uuid4().hex)
    
    def to_public_response(self) -> Dict[str, Any]:
        """Get sanitized public response."""
        return {
            "id": self.id,
            "category": self.category.value,
            "priority": self.priority.value,
            "title": self.public_title,
            "summary": self.public_summary,
            "created_at": self.created_at.isoformat(),
            "requires_action": self.priority in [MessagePriority.HIGH, MessagePriority.CRITICAL],
            "viewed": self.portal_viewed
        }
    
    def to_sensitive_response(self, include_details: bool = True) -> Dict[str, Any]:
        """Get full response with sensitive data (portal only)."""
        response = {
            "id": self.id,
            "category": self.category.value,
            "priority": self.priority.value,
            "title": self.sensitive_title,
            "body": self.sensitive_body,
            "created_at": self.created_at.isoformat(),
            "channels_delivered": [c.value for c in self.channels_delivered],
            "viewed": self.portal_viewed,
            "viewed_at": self.portal_viewed_at.isoformat() if self.portal_viewed_at else None
        }
        
        if include_details:
            response["details"] = self.sensitive_details
        
        return response
    
    def generate_email_content(self) -> Dict[str, str]:
        """Generate sanitized email content."""
        return {
            "subject": f"[SentinelIQ] {self.public_title}",
            "body": f"""
{self.public_summary}

This message may contain important information about your account.
Please log in to your SentinelIQ portal to view the full details.

Portal Link: https://portal.sentineliq.com/messages/{self.id}

---
This is an automated message from SentinelIQ.
Do not reply to this email.
"""
        }
    
    def generate_sms_content(self) -> str:
        """Generate minimal SMS content."""
        priority_prefix = "⚠️ " if self.priority in [
            MessagePriority.HIGH, MessagePriority.CRITICAL
        ] else ""
        return f"{priority_prefix}SentinelIQ: {self.public_title}. Log in to view details."


class MessageStore:
    """
    In-memory message store.
    
    In production, this would be backed by PostgreSQL
    with encryption at rest for sensitive fields.
    """
    
    def __init__(self):
        self.messages: Dict[str, SecureMessage] = {}
        self.user_messages: Dict[str, List[str]] = {}  # user_id -> message_ids
    
    def create_message(self, message: SecureMessage) -> SecureMessage:
        """Store a new message."""
        self.messages[message.id] = message
        
        if message.user_id not in self.user_messages:
            self.user_messages[message.user_id] = []
        self.user_messages[message.user_id].append(message.id)
        
        logger.info(f"Message created: {message.id} for user {message.user_id}")
        return message
    
    def get_message(self, message_id: str) -> Optional[SecureMessage]:
        """Get a message by ID."""
        return self.messages.get(message_id)
    
    def get_user_messages(
        self,
        user_id: str,
        category: Optional[MessageCategory] = None,
        priority: Optional[MessagePriority] = None,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> List[SecureMessage]:
        """Get messages for a user with filters."""
        message_ids = self.user_messages.get(user_id, [])
        messages = [self.messages[mid] for mid in message_ids if mid in self.messages]
        
        # Apply filters
        if category:
            messages = [m for m in messages if m.category == category]
        
        if priority:
            messages = [m for m in messages if m.priority == priority]
        
        if unread_only:
            messages = [m for m in messages if not m.portal_viewed]
        
        # Sort by created_at descending
        messages.sort(key=lambda m: m.created_at, reverse=True)
        
        # Pagination
        return messages[offset:offset + limit]
    
    def mark_viewed(self, message_id: str) -> bool:
        """Mark a message as viewed."""
        message = self.messages.get(message_id)
        if message:
            message.portal_viewed = True
            message.portal_viewed_at = datetime.utcnow()
            return True
        return False
    
    def get_unread_count(self, user_id: str) -> int:
        """Get unread message count for a user."""
        messages = self.get_user_messages(user_id, unread_only=True, limit=1000)
        return len(messages)


# Global message store
_message_store: Optional[MessageStore] = None


def get_message_store() -> MessageStore:
    """Get or create message store singleton."""
    global _message_store
    if _message_store is None:
        _message_store = MessageStore()
    return _message_store


class MessageService:
    """
    Service for creating and delivering secure messages.
    """
    
    def __init__(self, store: Optional[MessageStore] = None):
        self.store = store or get_message_store()
    
    async def send_fraud_alert(
        self,
        user_id: str,
        org_id: str,
        transaction_id: str,
        amount: float,
        risk_score: float,
        risk_factors: List[str],
        channels: List[MessageChannel] = None
    ) -> SecureMessage:
        """
        Send a fraud alert with proper content separation.
        """
        if channels is None:
            channels = [MessageChannel.PORTAL, MessageChannel.EMAIL]
        
        # Create message with separated content
        message = SecureMessage(
            id=f"msg_{uuid4().hex[:12]}",
            user_id=user_id,
            org_id=org_id,
            category=MessageCategory.FRAUD_ALERT,
            priority=self._calculate_priority(risk_score),
            created_at=datetime.utcnow(),
            
            # Public content (no sensitive data)
            public_title="Suspicious Activity Detected",
            public_summary="We detected unusual activity on your account. Please review your recent transactions in the portal.",
            
            # Sensitive content (portal only)
            sensitive_title=f"Fraud Alert: Transaction {transaction_id}",
            sensitive_body=f"""
A transaction on your account has been flagged for review.

Transaction ID: {transaction_id}
Amount: ${amount:,.2f}
Risk Score: {risk_score:.0%}

Risk Factors:
{chr(10).join(f'  • {factor}' for factor in risk_factors)}

Please review this transaction and confirm if it was authorized.
""",
            sensitive_details={
                "transaction_id": transaction_id,
                "amount": amount,
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "detected_at": datetime.utcnow().isoformat()
            },
            requires_mfa=risk_score >= 0.8
        )
        
        # Store message
        self.store.create_message(message)
        
        # Deliver to channels
        await self._deliver_to_channels(message, channels)
        
        return message
    
    async def send_security_alert(
        self,
        user_id: str,
        org_id: str,
        alert_type: str,
        details: Dict[str, Any],
        channels: List[MessageChannel] = None
    ) -> SecureMessage:
        """
        Send a security alert (login anomaly, password change, etc.)
        """
        if channels is None:
            channels = [MessageChannel.PORTAL, MessageChannel.EMAIL]
        
        # Sanitize public message
        public_titles = {
            "login_anomaly": "Unusual Sign-In Detected",
            "password_changed": "Password Changed",
            "mfa_disabled": "Security Settings Updated",
            "new_device": "New Device Sign-In",
            "failed_logins": "Multiple Failed Sign-In Attempts"
        }
        
        public_summaries = {
            "login_anomaly": "We noticed a sign-in from an unusual location. Please verify this was you.",
            "password_changed": "Your password was recently changed. If you didn't make this change, secure your account immediately.",
            "mfa_disabled": "Multi-factor authentication settings were updated on your account.",
            "new_device": "Your account was accessed from a new device. Verify this was you.",
            "failed_logins": "We blocked several attempts to access your account with incorrect credentials."
        }
        
        message = SecureMessage(
            id=f"msg_{uuid4().hex[:12]}",
            user_id=user_id,
            org_id=org_id,
            category=MessageCategory.SECURITY_ALERT,
            priority=MessagePriority.HIGH,
            created_at=datetime.utcnow(),
            
            public_title=public_titles.get(alert_type, "Security Alert"),
            public_summary=public_summaries.get(alert_type, "Please review your account security."),
            
            sensitive_title=f"Security Alert: {alert_type.replace('_', ' ').title()}",
            sensitive_body=self._format_security_details(alert_type, details),
            sensitive_details=details,
            requires_mfa=alert_type in ["mfa_disabled", "password_changed"]
        )
        
        self.store.create_message(message)
        await self._deliver_to_channels(message, channels)
        
        return message
    
    async def _deliver_to_channels(
        self,
        message: SecureMessage,
        channels: List[MessageChannel]
    ):
        """Deliver message to specified channels."""
        for channel in channels:
            try:
                if channel == MessageChannel.PORTAL:
                    # Portal messages are stored in-app (already done)
                    message.channels_delivered.append(channel)
                
                elif channel == MessageChannel.EMAIL:
                    # Send sanitized email
                    email_content = message.generate_email_content()
                    # In production: await email_service.send(...)
                    logger.info(f"Email queued for message {message.id}")
                    message.channels_delivered.append(channel)
                
                elif channel == MessageChannel.SMS:
                    # Send minimal SMS
                    sms_content = message.generate_sms_content()
                    # In production: await sms_service.send(...)
                    logger.info(f"SMS queued for message {message.id}")
                    message.channels_delivered.append(channel)
                
                elif channel == MessageChannel.PUSH:
                    # Send push notification
                    # In production: await push_service.send(...)
                    logger.info(f"Push notification queued for message {message.id}")
                    message.channels_delivered.append(channel)
                
                elif channel == MessageChannel.WEBHOOK:
                    # Send webhook with public content only
                    # In production: await webhook_service.send(...)
                    logger.info(f"Webhook queued for message {message.id}")
                    message.channels_delivered.append(channel)
                    
            except Exception as e:
                logger.error(f"Failed to deliver {channel} for message {message.id}: {e}")
    
    def _calculate_priority(self, risk_score: float) -> MessagePriority:
        """Calculate message priority from risk score."""
        if risk_score >= 0.9:
            return MessagePriority.CRITICAL
        elif risk_score >= 0.7:
            return MessagePriority.HIGH
        elif risk_score >= 0.4:
            return MessagePriority.MEDIUM
        return MessagePriority.LOW
    
    def _format_security_details(
        self,
        alert_type: str,
        details: Dict[str, Any]
    ) -> str:
        """Format security alert details."""
        lines = [f"Alert Type: {alert_type.replace('_', ' ').title()}", ""]
        
        if "ip_address" in details:
            lines.append(f"IP Address: {details['ip_address']}")
        
        if "location" in details:
            lines.append(f"Location: {details['location']}")
        
        if "device" in details:
            lines.append(f"Device: {details['device']}")
        
        if "timestamp" in details:
            lines.append(f"Time: {details['timestamp']}")
        
        if "user_agent" in details:
            lines.append(f"Browser: {details['user_agent'][:50]}...")
        
        lines.append("")
        lines.append("If this wasn't you, please secure your account immediately.")
        
        return "\n".join(lines)


# Global message service
_message_service: Optional[MessageService] = None


def get_message_service() -> MessageService:
    """Get or create message service singleton."""
    global _message_service
    if _message_service is None:
        _message_service = MessageService()
    return _message_service


# === API Models ===

class MessageListResponse(BaseModel):
    """Response for message list."""
    messages: List[Dict[str, Any]]
    total: int
    unread_count: int


class MessageDetailResponse(BaseModel):
    """Response for single message detail."""
    message: Dict[str, Any]
    access_logged: bool


class SendAlertRequest(BaseModel):
    """Request to send an alert."""
    user_id: str
    org_id: str
    category: MessageCategory
    priority: MessagePriority = MessagePriority.MEDIUM
    public_title: str
    public_summary: str
    sensitive_title: str
    sensitive_body: str
    sensitive_details: Dict[str, Any] = Field(default_factory=dict)
    channels: List[MessageChannel] = Field(default_factory=lambda: [MessageChannel.PORTAL])


# === API Routes ===

@router.get("/inbox", response_model=MessageListResponse)
async def get_inbox(
    category: Optional[MessageCategory] = Query(None),
    priority: Optional[MessagePriority] = Query(None),
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user)
):
    """
    Get user's message inbox.
    
    Returns sanitized public content only.
    View individual messages for full details.
    """
    store = get_message_store()
    
    messages = store.get_user_messages(
        user_id=str(current_user.id),
        category=category,
        priority=priority,
        unread_only=unread_only,
        limit=limit,
        offset=offset
    )
    
    unread_count = store.get_unread_count(str(current_user.id))
    
    return {
        "messages": [m.to_public_response() for m in messages],
        "total": len(messages),
        "unread_count": unread_count
    }


@router.get("/{message_id}", response_model=MessageDetailResponse)
async def get_message_detail(
    message_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get full message details.
    
    This endpoint returns sensitive content and is:
    - Authenticated (requires login)
    - Audited (access is logged)
    - May require MFA for high-risk messages
    """
    store = get_message_store()
    message = store.get_message(message_id)
    
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    # Verify ownership
    if message.user_id != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check MFA requirement
    if message.requires_mfa:
        # In production: verify MFA was completed recently
        pass
    
    # Mark as viewed
    store.mark_viewed(message_id)
    
    # Log access
    log_event(
        action="message_viewed",
        user_id=current_user.id,
        target=message_id,
        details={
            "category": message.category.value,
            "priority": message.priority.value
        }
    )
    
    return {
        "message": message.to_sensitive_response(),
        "access_logged": True
    }


@router.post("/send")
async def send_message(
    request: SendAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Send a new secure message.
    
    Requires appropriate permissions.
    """
    # Check permissions (admin or system)
    if current_user.role not in ["admin", "system"]:
        raise HTTPException(
            status_code=403,
            detail="Only admins can send messages"
        )
    
    store = get_message_store()
    
    message = SecureMessage(
        id=f"msg_{uuid4().hex[:12]}",
        user_id=request.user_id,
        org_id=request.org_id,
        category=request.category,
        priority=request.priority,
        created_at=datetime.utcnow(),
        public_title=request.public_title,
        public_summary=request.public_summary,
        sensitive_title=request.sensitive_title,
        sensitive_body=request.sensitive_body,
        sensitive_details=request.sensitive_details
    )
    
    store.create_message(message)
    
    # Deliver to channels in background
    service = get_message_service()
    for channel in request.channels:
        if channel != MessageChannel.PORTAL:
            background_tasks.add_task(
                service._deliver_to_channels,
                message,
                [channel]
            )
    
    return {
        "status": "sent",
        "message_id": message.id,
        "channels": [c.value for c in request.channels]
    }


@router.post("/{message_id}/mark-read")
async def mark_message_read(
    message_id: str,
    current_user: User = Depends(get_current_user)
):
    """Mark a message as read without viewing full details."""
    store = get_message_store()
    message = store.get_message(message_id)
    
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    if message.user_id != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    store.mark_viewed(message_id)
    
    return {"status": "marked_read", "message_id": message_id}


@router.get("/stats/summary")
async def get_message_stats(
    current_user: User = Depends(get_current_user)
):
    """Get message statistics for the current user."""
    store = get_message_store()
    
    all_messages = store.get_user_messages(str(current_user.id), limit=1000)
    unread_count = store.get_unread_count(str(current_user.id))
    
    # Count by category
    by_category = {}
    for msg in all_messages:
        cat = msg.category.value
        by_category[cat] = by_category.get(cat, 0) + 1
    
    # Count by priority
    by_priority = {}
    for msg in all_messages:
        pri = msg.priority.value
        by_priority[pri] = by_priority.get(pri, 0) + 1
    
    return {
        "total": len(all_messages),
        "unread": unread_count,
        "by_category": by_category,
        "by_priority": by_priority
    }


__all__ = [
    'router',
    'SecureMessage',
    'MessageService',
    'MessageStore',
    'MessageChannel',
    'MessagePriority',
    'MessageCategory',
    'get_message_service',
    'get_message_store'
]
