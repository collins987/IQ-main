"""
ABAC (Attribute-Based Access Control) - Fine-Grained Authorization

Extends RBAC with contextual attributes for:
- Regional data access (GDPR compliance)
- Classification-based access
- Time-based restrictions
- Device/location constraints

Architecture:
- Policies defined declaratively
- Evaluated at request time
- Integrates with existing RBAC
- Audit logging for all decisions

Compliance: GDPR Article 25 (Data Protection by Design)
"""

import logging
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from datetime import datetime, time
import re

from fastapi import HTTPException, status, Request, Depends
from sqlalchemy.orm import Session

from app.models import User
from app.dependencies import get_current_user, get_db
from app.core.logging import log_event

logger = logging.getLogger("sentineliq.abac")


class AttributeOperator(str, Enum):
    """Operators for attribute comparison."""
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    MATCHES = "matches"  # Regex
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    BETWEEN = "between"


@dataclass
class AttributeCondition:
    """Single attribute condition."""
    attribute: str  # e.g., "user.region", "resource.classification"
    operator: AttributeOperator
    value: Any
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate this condition against a context."""
        # Get attribute value from context using dot notation
        attr_value = self._get_nested_value(context, self.attribute)
        
        if attr_value is None:
            return False
        
        if self.operator == AttributeOperator.EQUALS:
            return attr_value == self.value
        
        elif self.operator == AttributeOperator.NOT_EQUALS:
            return attr_value != self.value
        
        elif self.operator == AttributeOperator.IN:
            return attr_value in self.value
        
        elif self.operator == AttributeOperator.NOT_IN:
            return attr_value not in self.value
        
        elif self.operator == AttributeOperator.CONTAINS:
            return self.value in attr_value
        
        elif self.operator == AttributeOperator.MATCHES:
            return bool(re.match(self.value, str(attr_value)))
        
        elif self.operator == AttributeOperator.GREATER_THAN:
            return attr_value > self.value
        
        elif self.operator == AttributeOperator.LESS_THAN:
            return attr_value < self.value
        
        elif self.operator == AttributeOperator.BETWEEN:
            low, high = self.value
            return low <= attr_value <= high
        
        return False
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """Get value from nested dict using dot notation."""
        keys = path.split(".")
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            elif hasattr(value, key):
                value = getattr(value, key)
            else:
                return None
        
        return value


@dataclass
class ABACPolicy:
    """
    ABAC Policy definition.
    
    A policy grants access when ALL conditions are met.
    Multiple policies can apply to the same resource (OR logic).
    """
    
    id: str
    name: str
    description: str
    
    # What this policy applies to
    resource_type: str  # e.g., "user_data", "transaction", "audit_log"
    action: str  # e.g., "read", "write", "delete"
    
    # Conditions that must ALL be true
    conditions: List[AttributeCondition] = field(default_factory=list)
    
    # Priority (higher = evaluated first)
    priority: int = 0
    
    # Is policy active?
    enabled: bool = True
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate policy against context."""
        if not self.enabled:
            return False
        
        # All conditions must be true
        return all(cond.evaluate(context) for cond in self.conditions)


class ABACPolicyStore:
    """
    In-memory policy store.
    
    In production, this could be backed by a database
    for dynamic policy management.
    """
    
    def __init__(self):
        self.policies: Dict[str, ABACPolicy] = {}
        self._load_default_policies()
    
    def _load_default_policies(self):
        """Load default ABAC policies."""
        
        # Policy: EU analysts can only view EU user data
        self.add_policy(ABACPolicy(
            id="eu_data_access",
            name="EU Data Residency",
            description="EU analysts can only access EU user data (GDPR)",
            resource_type="user_data",
            action="read",
            priority=100,
            conditions=[
                AttributeCondition(
                    attribute="user.region",
                    operator=AttributeOperator.EQUALS,
                    value="EU"
                ),
                AttributeCondition(
                    attribute="resource.data_region",
                    operator=AttributeOperator.EQUALS,
                    value="EU"
                )
            ]
        ))
        
        # Policy: US analysts can access US data
        self.add_policy(ABACPolicy(
            id="us_data_access",
            name="US Data Access",
            description="US analysts can access US user data",
            resource_type="user_data",
            action="read",
            priority=100,
            conditions=[
                AttributeCondition(
                    attribute="user.region",
                    operator=AttributeOperator.EQUALS,
                    value="US"
                ),
                AttributeCondition(
                    attribute="resource.data_region",
                    operator=AttributeOperator.EQUALS,
                    value="US"
                )
            ]
        ))
        
        # Policy: Admins can access all regions
        self.add_policy(ABACPolicy(
            id="admin_all_regions",
            name="Admin Global Access",
            description="Admins can access data from any region",
            resource_type="user_data",
            action="read",
            priority=200,  # Higher priority
            conditions=[
                AttributeCondition(
                    attribute="user.role",
                    operator=AttributeOperator.EQUALS,
                    value="admin"
                )
            ]
        ))
        
        # Policy: Business hours only for sensitive operations
        self.add_policy(ABACPolicy(
            id="business_hours_sensitive",
            name="Business Hours Restriction",
            description="Sensitive operations only during business hours",
            resource_type="sensitive_data",
            action="write",
            priority=50,
            conditions=[
                AttributeCondition(
                    attribute="request.hour",
                    operator=AttributeOperator.BETWEEN,
                    value=(9, 17)  # 9 AM to 5 PM
                ),
                AttributeCondition(
                    attribute="request.weekday",
                    operator=AttributeOperator.IN,
                    value=[0, 1, 2, 3, 4]  # Monday to Friday
                )
            ]
        ))
        
        # Policy: High-risk transactions require additional verification
        self.add_policy(ABACPolicy(
            id="high_risk_transaction",
            name="High Risk Transaction Control",
            description="Transactions over $10k require manager approval",
            resource_type="transaction",
            action="approve",
            priority=100,
            conditions=[
                AttributeCondition(
                    attribute="resource.amount",
                    operator=AttributeOperator.LESS_THAN,
                    value=10000
                )
            ]
        ))
        
        # Policy: Block access from risky devices
        self.add_policy(ABACPolicy(
            id="trusted_device",
            name="Trusted Device Requirement",
            description="Sensitive data requires trusted device",
            resource_type="sensitive_data",
            action="read",
            priority=150,
            conditions=[
                AttributeCondition(
                    attribute="request.device_trusted",
                    operator=AttributeOperator.EQUALS,
                    value=True
                )
            ]
        ))
    
    def add_policy(self, policy: ABACPolicy):
        """Add a policy to the store."""
        self.policies[policy.id] = policy
        logger.debug(f"ABAC policy added: {policy.id}")
    
    def get_policy(self, policy_id: str) -> Optional[ABACPolicy]:
        """Get a policy by ID."""
        return self.policies.get(policy_id)
    
    def get_policies_for_resource(
        self,
        resource_type: str,
        action: str
    ) -> List[ABACPolicy]:
        """Get all policies applicable to a resource/action."""
        policies = [
            p for p in self.policies.values()
            if p.resource_type == resource_type and p.action == action and p.enabled
        ]
        # Sort by priority (descending)
        return sorted(policies, key=lambda p: p.priority, reverse=True)
    
    def remove_policy(self, policy_id: str):
        """Remove a policy."""
        if policy_id in self.policies:
            del self.policies[policy_id]
            logger.info(f"ABAC policy removed: {policy_id}")


class ABACEnforcer:
    """
    ABAC enforcement engine.
    
    Evaluates policies and makes access decisions.
    """
    
    def __init__(self, policy_store: Optional[ABACPolicyStore] = None):
        self.policy_store = policy_store or ABACPolicyStore()
    
    def build_context(
        self,
        user: User,
        request: Request,
        resource: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build evaluation context from request components.
        """
        now = datetime.utcnow()
        
        context = {
            "user": {
                "id": user.id,
                "role": user.role,
                "org_id": user.org_id,
                "email": user.email,
                "region": getattr(user, 'region', 'US'),  # Default to US
                "department": getattr(user, 'department', None),
                "clearance_level": getattr(user, 'clearance_level', 'standard'),
            },
            "request": {
                "ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "path": request.url.path,
                "method": request.method,
                "hour": now.hour,
                "weekday": now.weekday(),
                "timestamp": now.isoformat(),
                "device_trusted": request.headers.get("X-Device-Trusted", "false") == "true",
            },
            "resource": resource or {}
        }
        
        return context
    
    def check_access(
        self,
        user: User,
        request: Request,
        resource_type: str,
        action: str,
        resource: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if access should be granted.
        
        Returns:
            Tuple of (allowed, reason)
        """
        context = self.build_context(user, request, resource)
        
        # Get applicable policies
        policies = self.policy_store.get_policies_for_resource(resource_type, action)
        
        if not policies:
            # No policies = allow (fail-open for undefined resources)
            logger.debug(f"No ABAC policies for {resource_type}:{action}, allowing")
            return True, "no_policy"
        
        # Evaluate policies (first match wins due to priority sorting)
        for policy in policies:
            if policy.evaluate(context):
                logger.debug(f"ABAC policy {policy.id} granted access")
                return True, policy.id
        
        # No policy granted access
        logger.warning(
            f"ABAC denied: user={user.id}, resource={resource_type}, action={action}"
        )
        return False, "no_matching_policy"
    
    def enforce(
        self,
        user: User,
        request: Request,
        resource_type: str,
        action: str,
        resource: Optional[Dict[str, Any]] = None
    ):
        """
        Enforce ABAC policy - raises HTTPException if denied.
        """
        allowed, reason = self.check_access(
            user, request, resource_type, action, resource
        )
        
        if not allowed:
            # Log the denial
            log_event(
                action="abac_denied",
                user_id=user.id,
                target=f"{resource_type}:{action}",
                details={
                    "reason": reason,
                    "resource": resource
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied by policy: {reason}"
            )


# Global enforcer instance
_enforcer: Optional[ABACEnforcer] = None


def get_abac_enforcer() -> ABACEnforcer:
    """Get or create ABAC enforcer singleton."""
    global _enforcer
    if _enforcer is None:
        _enforcer = ABACEnforcer()
    return _enforcer


# Type alias for tuple return
from typing import Tuple


def require_abac(
    resource_type: str,
    action: str,
    resource_func: Optional[Callable[..., Dict[str, Any]]] = None
):
    """
    Decorator/dependency for ABAC enforcement.
    
    Usage:
        @router.get("/users/{user_id}/data")
        def get_user_data(
            user_id: str,
            _: None = Depends(require_abac("user_data", "read"))
        ):
            ...
    """
    def dependency(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        enforcer = get_abac_enforcer()
        
        # Get resource if function provided
        resource = None
        if resource_func:
            resource = resource_func(request, db)
        
        enforcer.enforce(
            current_user,
            request,
            resource_type,
            action,
            resource
        )
        
        return current_user
    
    return dependency


def abac_check(resource_type: str, action: str):
    """
    Decorator for ABAC enforcement on functions.
    
    Usage:
        @abac_check("user_data", "read")
        def get_sensitive_data(user: User, request: Request, ...):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Extract user and request from kwargs
            user = kwargs.get('current_user') or kwargs.get('user')
            request = kwargs.get('request')
            
            if not user or not request:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User context required for ABAC"
                )
            
            enforcer = get_abac_enforcer()
            enforcer.enforce(user, request, resource_type, action)
            
            return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            user = kwargs.get('current_user') or kwargs.get('user')
            request = kwargs.get('request')
            
            if not user or not request:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User context required for ABAC"
                )
            
            enforcer = get_abac_enforcer()
            enforcer.enforce(user, request, resource_type, action)
            
            return func(*args, **kwargs)
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


__all__ = [
    'ABACPolicy',
    'ABACPolicyStore',
    'ABACEnforcer',
    'AttributeCondition',
    'AttributeOperator',
    'get_abac_enforcer',
    'require_abac',
    'abac_check'
]
