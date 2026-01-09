"""
Milestone 8: Alerts & Anomaly Detection
Detects and alerts on suspicious activity
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from app.models import User, AuditLog, LoginAttempt
from app.core.logging import logger


class AlertService:
    """Service for detecting and managing alerts"""
    
    # Alert thresholds (configurable)
    FAILED_LOGIN_THRESHOLD = 5  # Alert after 5 failed attempts
    FAILED_LOGIN_WINDOW = 15  # In this many minutes
    FORBIDDEN_ACCESS_THRESHOLD = 3  # Alert after 3 forbidden attempts
    FORBIDDEN_ACCESS_WINDOW = 60  # In this many minutes
    ERROR_RATE_THRESHOLD = 10  # Alert if error rate > 10%
    
    @staticmethod
    def check_failed_login_attempts(db: Session) -> List[Dict[str, Any]]:
        """
        Check for users with excessive failed login attempts
        """
        alerts = []
        cutoff = datetime.utcnow() - timedelta(minutes=AlertService.FAILED_LOGIN_WINDOW)
        
        # Get failed attempts by email
        results = db.query(
            LoginAttempt.email,
            func.count(LoginAttempt.id).label("count")
        ).filter(
            and_(
                LoginAttempt.timestamp >= cutoff,
                LoginAttempt.success == False
            )
        ).group_by(LoginAttempt.email).having(
            func.count(LoginAttempt.id) >= AlertService.FAILED_LOGIN_THRESHOLD
        ).all()
        
        for email, count in results:
            # Find user
            user = db.query(User).filter(User.email == email).first()
            
            alert = {
                "alert_type": "excessive_failed_logins",
                "severity": "high" if count >= AlertService.FAILED_LOGIN_THRESHOLD * 2 else "medium",
                "email": email,
                "user_id": user.id if user else None,
                "failed_attempts": count,
                "window_minutes": AlertService.FAILED_LOGIN_WINDOW,
                "threshold": AlertService.FAILED_LOGIN_THRESHOLD,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            alerts.append(alert)
            
            # Log alert
            logger.warning(
                f"Alert: Excessive failed logins for {email}",
                extra={
                    "alert_type": "excessive_failed_logins",
                    "email": email,
                    "user_id": user.id if user else None,
                    "failed_attempts": count
                }
            )
        
        return alerts
    
    @staticmethod
    def check_forbidden_access_attempts(db: Session) -> List[Dict[str, Any]]:
        """
        Check for users with excessive forbidden access attempts
        """
        alerts = []
        cutoff = datetime.utcnow() - timedelta(minutes=AlertService.FORBIDDEN_ACCESS_WINDOW)
        
        # Get forbidden attempts by user
        results = db.query(
            AuditLog.actor_id,
            User.email,
            User.role,
            func.count(AuditLog.id).label("count")
        ).join(User).filter(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.action.contains("forbidden")
            )
        ).group_by(AuditLog.actor_id, User.email, User.role).having(
            func.count(AuditLog.id) >= AlertService.FORBIDDEN_ACCESS_THRESHOLD
        ).all()
        
        for user_id, email, role, count in results:
            alert = {
                "alert_type": "excessive_forbidden_access",
                "severity": "high" if count >= AlertService.FORBIDDEN_ACCESS_THRESHOLD * 2 else "medium",
                "user_id": user_id,
                "email": email,
                "role": role,
                "forbidden_attempts": count,
                "window_minutes": AlertService.FORBIDDEN_ACCESS_WINDOW,
                "threshold": AlertService.FORBIDDEN_ACCESS_THRESHOLD,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            alerts.append(alert)
            
            # Log alert
            logger.warning(
                f"Alert: Excessive forbidden access by {email}",
                extra={
                    "alert_type": "excessive_forbidden_access",
                    "user_id": user_id,
                    "email": email,
                    "role": role,
                    "forbidden_attempts": count
                }
            )
        
        return alerts
    
    @staticmethod
    def check_account_security(db: Session) -> List[Dict[str, Any]]:
        """
        Check for user account security issues
        """
        alerts = []
        
        # Check for inactive users
        cutoff = datetime.utcnow() - timedelta(days=30)
        inactive_users = db.query(User).filter(
            User.updated_at < cutoff
        ).all()
        
        for user in inactive_users:
            if user.is_active:
                alert = {
                    "alert_type": "inactive_user",
                    "severity": "low",
                    "user_id": user.id,
                    "email": user.email,
                    "role": user.role,
                    "last_activity": user.updated_at.isoformat(),
                    "inactive_days": (datetime.utcnow() - user.updated_at).days,
                    "timestamp": datetime.utcnow().isoformat()
                }
                alerts.append(alert)
        
        # Check for unverified emails
        unverified = db.query(User).filter(
            and_(
                User.email_verified == False,
                User.created_at < datetime.utcnow() - timedelta(hours=24)
            )
        ).all()
        
        for user in unverified:
            alert = {
                "alert_type": "unverified_email",
                "severity": "low",
                "user_id": user.id,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.isoformat(),
                "hours_unverified": (datetime.utcnow() - user.created_at).total_seconds() / 3600,
                "timestamp": datetime.utcnow().isoformat()
            }
            alerts.append(alert)
        
        return alerts
    
    @staticmethod
    def check_suspicious_role_changes(db: Session) -> List[Dict[str, Any]]:
        """
        Check for suspicious role changes in audit logs
        """
        alerts = []
        cutoff = datetime.utcnow() - timedelta(hours=24)
        
        # Look for role change actions
        role_changes = db.query(AuditLog).filter(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.action.contains("update_role")
            )
        ).all()
        
        for log in role_changes:
            # Alert on any role change (could be suspicious)
            actor = db.query(User).filter(User.id == log.actor_id).first()
            
            alert = {
                "alert_type": "role_change",
                "severity": "high",
                "actor_id": log.actor_id,
                "actor_email": actor.email if actor else None,
                "actor_role": actor.role if actor else None,
                "action": log.action,
                "target": log.target,
                "metadata": log.event_metadata,
                "timestamp": log.timestamp.isoformat()
            }
            
            alerts.append(alert)
            
            # Log alert
            logger.warning(
                f"Alert: Role change detected",
                extra={
                    "alert_type": "role_change",
                    "actor_id": log.actor_id,
                    "actor_email": actor.email if actor else None,
                    "target": log.target
                }
            )
        
        return alerts
    
    @staticmethod
    def get_all_alerts(db: Session) -> List[Dict[str, Any]]:
        """
        Get all active alerts
        """
        all_alerts = []
        all_alerts.extend(AlertService.check_failed_login_attempts(db))
        all_alerts.extend(AlertService.check_forbidden_access_attempts(db))
        all_alerts.extend(AlertService.check_account_security(db))
        all_alerts.extend(AlertService.check_suspicious_role_changes(db))
        
        return sorted(all_alerts, key=lambda x: x["timestamp"], reverse=True)
    
    @staticmethod
    def send_alert_notification(alert: Dict[str, Any]) -> bool:
        """
        Send alert notification (email, Slack, etc)
        For now, just logging - can be extended to send emails/webhooks
        """
        severity = alert.get("severity", "unknown").upper()
        alert_type = alert.get("alert_type", "unknown")
        
        message = f"[{severity}] {alert_type}: {alert}"
        
        if severity == "HIGH":
            logger.error(message, extra=alert)
        elif severity == "MEDIUM":
            logger.warning(message, extra=alert)
        else:
            logger.info(message, extra=alert)
        
        # TODO: Integrate with email/Slack/webhook service
        
        return True
