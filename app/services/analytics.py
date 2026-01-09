"""
Milestone 8: Analytics & Insights
Database queries for monitoring and analytics dashboards
"""

from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from datetime import datetime, timedelta
from app.models import (
    User, AuditLog, LoginAttempt, RefreshToken, EmailToken
)
from typing import Dict, List, Any, Optional


class AnalyticsService:
    """Service for generating analytics and monitoring data"""
    
    @staticmethod
    def get_active_users_count(db: Session, role: Optional[str] = None) -> int:
        """Get count of active users"""
        query = db.query(User).filter(User.is_active == True)
        if role:
            query = query.filter(User.role == role)
        return query.count()
    
    @staticmethod
    def get_users_by_role(db: Session) -> Dict[str, int]:
        """Get count of users by role"""
        results = db.query(
            User.role,
            func.count(User.id).label("count")
        ).group_by(User.role).all()
        
        return {role: count for role, count in results}
    
    @staticmethod
    def get_email_verification_stats(db: Session) -> Dict[str, Any]:
        """Get email verification statistics"""
        total_users = db.query(func.count(User.id)).scalar()
        verified_users = db.query(func.count(User.id)).filter(User.email_verified == True).scalar()
        unverified_users = total_users - (verified_users or 0)
        
        return {
            "total_users": total_users,
            "verified_users": verified_users or 0,
            "unverified_users": unverified_users,
            "verification_rate": (verified_users / total_users * 100) if total_users > 0 else 0
        }
    
    @staticmethod
    def get_login_stats(db: Session, hours: int = 24) -> Dict[str, Any]:
        """Get login statistics"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        total_attempts = db.query(func.count(LoginAttempt.id)).filter(
            LoginAttempt.timestamp >= cutoff
        ).scalar() or 0
        
        successful = db.query(func.count(LoginAttempt.id)).filter(
            and_(
                LoginAttempt.timestamp >= cutoff,
                LoginAttempt.success == True
            )
        ).scalar() or 0
        
        failed = total_attempts - successful
        
        return {
            "total_attempts": total_attempts,
            "successful": successful,
            "failed": failed,
            "success_rate": (successful / total_attempts * 100) if total_attempts > 0 else 0,
            "period_hours": hours
        }
    
    @staticmethod
    def get_failed_login_attempts_by_user(db: Session, limit: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
        """Get users with most failed login attempts"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        results = db.query(
            LoginAttempt.email,
            func.count(LoginAttempt.id).label("failed_count"),
            func.max(LoginAttempt.timestamp).label("last_attempt")
        ).filter(
            and_(
                LoginAttempt.timestamp >= cutoff,
                LoginAttempt.success == False
            )
        ).group_by(LoginAttempt.email).order_by(
            desc(func.count(LoginAttempt.id))
        ).limit(limit).all()
        
        return [
            {
                "email": email,
                "failed_attempts": count,
                "last_attempt": last_attempt
            }
            for email, count, last_attempt in results
        ]
    
    @staticmethod
    def get_session_stats(db: Session) -> Dict[str, Any]:
        """Get active session statistics"""
        total_tokens = db.query(func.count(RefreshToken.id)).filter(
            RefreshToken.is_revoked == False
        ).scalar() or 0
        
        expired_tokens = db.query(func.count(RefreshToken.id)).filter(
            and_(
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at < datetime.utcnow()
            )
        ).scalar() or 0
        
        active_tokens = total_tokens - expired_tokens
        
        return {
            "total_sessions": total_tokens,
            "active_sessions": active_tokens,
            "expired_sessions": expired_tokens
        }
    
    @staticmethod
    def get_audit_log_summary(db: Session, hours: int = 24) -> Dict[str, Any]:
        """Get audit log summary"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        total_events = db.query(func.count(AuditLog.id)).filter(
            AuditLog.timestamp >= cutoff
        ).scalar() or 0
        
        # Count by action
        actions = db.query(
            AuditLog.action,
            func.count(AuditLog.id).label("count")
        ).filter(AuditLog.timestamp >= cutoff).group_by(AuditLog.action).all()
        
        action_counts = {action: count for action, count in actions}
        
        return {
            "total_events": total_events,
            "period_hours": hours,
            "events_by_action": action_counts
        }
    
    @staticmethod
    def get_forbidden_access_attempts(db: Session, hours: int = 24, limit: int = 10) -> List[Dict[str, Any]]:
        """Get forbidden access attempts"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        results = db.query(
            AuditLog.actor_id,
            AuditLog.action,
            AuditLog.target,
            func.count(AuditLog.id).label("attempts"),
            func.max(AuditLog.timestamp).label("last_attempt")
        ).filter(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.action.contains("forbidden")
            )
        ).group_by(
            AuditLog.actor_id,
            AuditLog.action,
            AuditLog.target
        ).order_by(desc(func.count(AuditLog.id))).limit(limit).all()
        
        return [
            {
                "user_id": actor_id,
                "action": action,
                "target": target,
                "attempts": attempts,
                "last_attempt": last_attempt
            }
            for actor_id, action, target, attempts, last_attempt in results
        ]
    
    @staticmethod
    def get_user_activity(db: Session, user_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get activity for a specific user"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get user info
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}
        
        # Count audit logs
        audit_events = db.query(func.count(AuditLog.id)).filter(
            and_(
                AuditLog.actor_id == user_id,
                AuditLog.timestamp >= cutoff
            )
        ).scalar() or 0
        
        # Get recent audit logs
        recent_logs = db.query(AuditLog).filter(
            and_(
                AuditLog.actor_id == user_id,
                AuditLog.timestamp >= cutoff
            )
        ).order_by(desc(AuditLog.timestamp)).limit(10).all()
        
        return {
            "user_id": user_id,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "events_count": audit_events,
            "period_hours": hours,
            "recent_events": [
                {
                    "action": log.action,
                    "target": log.target,
                    "timestamp": log.timestamp,
                    "metadata": log.event_metadata
                }
                for log in recent_logs
            ]
        }
    
    @staticmethod
    def get_security_dashboard(db: Session) -> Dict[str, Any]:
        """Get comprehensive security dashboard data"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "users": AnalyticsService.get_users_by_role(db),
            "email_verification": AnalyticsService.get_email_verification_stats(db),
            "login_stats": AnalyticsService.get_login_stats(db, hours=24),
            "failed_logins": AnalyticsService.get_failed_login_attempts_by_user(db),
            "session_stats": AnalyticsService.get_session_stats(db),
            "audit_logs": AnalyticsService.get_audit_log_summary(db),
            "forbidden_access": AnalyticsService.get_forbidden_access_attempts(db)
        }
