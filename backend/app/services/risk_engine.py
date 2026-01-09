"""
Risk Engine Service - The core fraud detection and risk scoring system.
Implements hybrid risk scoring with hard rules, velocity checks, and behavioral analysis.
"""

import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from math import radians, sin, cos, sqrt, atan2

from app.schemas.event import (
    SentinelEvent, RiskScore, EventTypes, VelocityCheckResult
)
from app.models.events import (
    RiskDecision, CryptoAuditLog, RuleEvaluation, 
    DeviceFingerprint, VelocityCounter
)
from app.services.redis_stream import get_redis_stream_manager
from app.core.db import db_session
import yaml

logger = logging.getLogger("sentineliq.risk_engine")


class RiskEngine:
    """Core risk scoring and fraud detection engine."""
    
    def __init__(self, rules_path: str = "/app/rules/fraud_rules.yaml"):
        self.redis = get_redis_stream_manager()
        self.rules = self._load_rules(rules_path)
        self.scoring_config = self.rules.get("scoring", {})
    
    def _load_rules(self, rules_path: str) -> Dict:
        """Load fraud rules from YAML configuration."""
        try:
            with open(rules_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.warning(f"Rules file not found: {rules_path}")
            return {}
    
    async def evaluate_event(self, event: SentinelEvent) -> RiskScore:
        """
        Main entry point: Evaluate an event and return a risk score.
        
        Flow:
        1. Extract context (user, device, location)
        2. Evaluate hard rules (gatekeepers)
        3. Evaluate velocity checks
        4. Evaluate behavioral rules
        5. Calculate composite score
        6. Log decision with crypto-chaining
        """
        
        logger.info(f"Evaluating event: {event.event_id} ({event.event_type})")
        
        # Initialize tracking
        hard_rules_triggered = []
        velocity_alerts = []
        behavioral_flags = []
        all_triggered_rules = []
        
        risk_score = 0.0
        confidence = 0.0
        
        try:
            # Step 1: Evaluate hard rules (gatekeepers)
            hard_rule_results = self._evaluate_hard_rules(event)
            if hard_rule_results["triggered"]:
                hard_rules_triggered = hard_rule_results["triggered"]
                all_triggered_rules.extend(hard_rule_results["triggered"])
                risk_score = max(hard_rule_results["scores"])
                
                logger.warning(f"Hard rule triggered: {hard_rules_triggered}")
                
                # Hard rule block = immediate action
                decision_result = RiskScore(
                    event_id=event.event_id,
                    user_id=event.actor.user_id,
                    risk_score=risk_score,
                    risk_level="critical",
                    hard_rules_triggered=hard_rules_triggered,
                    recommended_action="block",
                    confidence=1.0,
                    triggered_rules=all_triggered_rules
                )
                
                # Log the decision
                await self._log_risk_decision(event, decision_result)
                return decision_result
            
            # Step 2: Evaluate velocity checks
            velocity_results = self._evaluate_velocity_checks(event)
            if velocity_results["triggered"]:
                velocity_alerts = velocity_results["triggered"]
                all_triggered_rules.extend(velocity_results["triggered"])
                risk_score = max(velocity_results["scores"]) if velocity_results["scores"] else risk_score
            
            # Step 3: Evaluate behavioral rules
            behavioral_results = self._evaluate_behavioral_rules(event)
            if behavioral_results["triggered"]:
                behavioral_flags = behavioral_results["triggered"]
                all_triggered_rules.extend(behavioral_results["triggered"])
                # Behavioral scores are weighted lower
                behavioral_score = max(behavioral_results["scores"]) if behavioral_results["scores"] else 0
                risk_score = (risk_score * 0.7) + (behavioral_score * 0.3)
            
            # Step 3.5: User-Agent Anomaly Detection (Levenshtein distance)
            ua_results = self._evaluate_user_agent_anomaly(event)
            if ua_results.get("is_anomaly"):
                all_triggered_rules.append("ua_anomaly_detected")
                behavioral_flags.append("user_agent_anomaly")
                risk_score = max(risk_score, ua_results.get("score", 0.5))
            
            # Step 3.6: ML-based Anomaly Detection (Isolation Forest)
            ml_results = await self._evaluate_ml_anomaly(event)
            if ml_results.get("is_anomaly"):
                all_triggered_rules.append("ml_anomaly_detected")
                behavioral_flags.append("ml_isolation_forest_anomaly")
                # Blend ML score with rule-based score
                ml_weight = 0.3  # ML contributes 30% to final score
                risk_score = (risk_score * (1 - ml_weight)) + (ml_results["score"] * ml_weight)
            
            # Step 4: Apply rule combinations (meta-rules)
            combo_boost = self._evaluate_rule_combinations(all_triggered_rules)
            risk_score = min(1.0, risk_score + combo_boost)
            
            # Step 5: Determine risk level and recommended action
            risk_level, action = self._determine_action(risk_score)
            
            # Calculate confidence
            confidence = self._calculate_confidence(
                len(all_triggered_rules),
                risk_score
            )
            
            # Create the risk score result
            decision_result = RiskScore(
                event_id=event.event_id,
                user_id=event.actor.user_id,
                risk_score=risk_score,
                risk_level=risk_level,
                hard_rules_triggered=hard_rules_triggered,
                velocity_alerts=velocity_alerts,
                behavioral_flags=behavioral_flags,
                recommended_action=action,
                confidence=confidence,
                triggered_rules=all_triggered_rules
            )
            
            # Log the decision
            await self._log_risk_decision(event, decision_result)
            
            return decision_result
            
        except Exception as e:
            logger.error(f"Error evaluating event: {e}")
            # Fail open (allow) but log the error
            return RiskScore(
                event_id=event.event_id,
                user_id=event.actor.user_id,
                risk_score=0.2,
                risk_level="low",
                recommended_action="allow",
                confidence=0.5,
                triggered_rules=["evaluation_error"]
            )
    
    def _evaluate_hard_rules(self, event: SentinelEvent) -> Dict[str, Any]:
        """Evaluate hard rules (gatekeepers)."""
        triggered = []
        scores = []
        
        hard_rules = self.rules.get("rules", {}).get("hard_rules", [])
        
        for rule in hard_rules:
            if not rule.get("enabled", True):
                continue
            
            if self._match_rule(event, rule):
                triggered.append(rule["id"])
                scores.append(rule.get("risk_score", 0.5))
                logger.warning(f"Hard rule matched: {rule['id']} - {rule['name']}")
        
        return {"triggered": triggered, "scores": scores}
    
    def _evaluate_velocity_checks(self, event: SentinelEvent) -> Dict[str, Any]:
        """Evaluate velocity checks (physically impossible travel, etc.)."""
        triggered = []
        scores = []
        
        velocity_rules = self.rules.get("rules", {}).get("velocity_checks", [])
        
        for rule in velocity_rules:
            if not rule.get("enabled", True):
                continue
            
            if rule["id"] == "impossible_travel":
                if self._check_impossible_travel(event):
                    triggered.append(rule["id"])
                    scores.append(rule.get("risk_score", 0.7))
                    logger.warning(f"Velocity check matched: {rule['id']}")
            
            elif rule["id"] == "rapid_transactions":
                if self._check_rapid_transactions(event):
                    triggered.append(rule["id"])
                    scores.append(rule.get("risk_score", 0.7))
            
            elif rule["id"] == "multi_device_login":
                if self._check_multi_device_login(event):
                    triggered.append(rule["id"])
                    scores.append(rule.get("risk_score", 0.75))
        
        return {"triggered": triggered, "scores": scores}
    
    def _evaluate_behavioral_rules(self, event: SentinelEvent) -> Dict[str, Any]:
        """Evaluate behavioral/anomaly detection rules."""
        triggered = []
        scores = []
        
        behavioral_rules = self.rules.get("rules", {}).get("behavioral_rules", [])
        
        for rule in behavioral_rules:
            if not rule.get("enabled", True):
                continue
            
            if self._match_rule(event, rule):
                triggered.append(rule["id"])
                scores.append(rule.get("risk_score", 0.5))
                logger.info(f"Behavioral rule matched: {rule['id']} - {rule['name']}")
        
        return {"triggered": triggered, "scores": scores}
    
    def _match_rule(self, event: SentinelEvent, rule: Dict) -> bool:
        """Check if an event matches a rule's conditions."""
        conditions = rule.get("conditions", {})
        
        for condition_key, condition_value in conditions.items():
            # This is simplified; in production you'd need more sophisticated matching
            if condition_key == "event_type":
                if event.event_type != condition_value:
                    return False
            
            elif condition_key == "country_code":
                if "in" in condition_value:
                    if event.context.country_code not in condition_value["in"]:
                        return False
        
        return True
    
    def _check_impossible_travel(self, event: SentinelEvent) -> bool:
        """Check for physically impossible travel between logins."""
        if event.event_type != EventTypes.AUTHENTICATION_LOGIN:
            return False
        
        user_id = event.actor.user_id
        
        # Get user's last known location from Redis
        last_location = self.redis.get_user_location(user_id)
        if not last_location:
            # First location, cache it
            self.redis.cache_user_location(
                user_id,
                event.context.geo_lat,
                event.context.geo_lon
            )
            return False
        
        # Calculate distance using haversine formula
        distance = self._haversine_distance(
            last_location["lat"],
            last_location["lon"],
            event.context.geo_lat,
            event.context.geo_lon
        )
        
        # For now, if distance > 3000 miles, flag as suspicious
        if distance > 3000:
            logger.warning(f"Impossible travel detected: {distance:.0f} miles")
            # Update location
            self.redis.cache_user_location(
                user_id,
                event.context.geo_lat,
                event.context.geo_lon
            )
            return True
        
        return False
    
    def _check_rapid_transactions(self, event: SentinelEvent) -> bool:
        """Check for unusually high transaction frequency."""
        if event.event_type != EventTypes.TRANSACTION_ATTEMPTED:
            return False
        
        user_id = event.actor.user_id
        
        # Check transaction count in last hour
        key = f"user:{user_id}:transactions:hourly"
        count = self.redis.increment_velocity_counter(key)
        
        # Threshold from rules
        if count > 20:  # 20 transactions per hour
            logger.warning(f"Rapid transactions detected: {count} in 1 hour")
            return True
        
        return False
    
    def _check_multi_device_login(self, event: SentinelEvent) -> bool:
        """Check for simultaneous logins from multiple devices."""
        if event.event_type != EventTypes.AUTHENTICATION_LOGIN:
            return False
        
        user_id = event.actor.user_id
        device_hash = event.actor.device_fingerprint
        
        # Check if device is known
        is_known = self.redis.is_known_device(user_id, device_hash)
        
        if not is_known:
            # Get count of logins from different devices in last 5 minutes
            key = f"user:{user_id}:devices:5min"
            self.redis.redis.sadd(key, device_hash)
            self.redis.redis.expire(key, 300)
            
            devices = self.redis.redis.scard(key)
            
            if devices > 3:
                logger.warning(f"Multi-device login detected: {devices} devices in 5 min")
                return True
            
            # Cache this device as known
            self.redis.cache_device_fingerprint(user_id, device_hash)
        
        return False
    
    def _evaluate_rule_combinations(self, triggered_rules: List[str]) -> float:
        """Boost score if multiple suspicious rules trigger together."""
        combo_boost = 0.0
        
        combinations = self.rules.get("rules", {}).get("rule_combinations", [])
        
        for combo in combinations:
            required_rules = set(combo.get("triggered_rules", []))
            if required_rules.issubset(set(triggered_rules)):
                combo_boost = max(combo_boost, combo.get("base_score", 0.0) - 0.5)
                logger.warning(f"Rule combination matched: {combo['id']}")
        
        return combo_boost
    
    def _determine_action(self, risk_score: float) -> tuple[str, str]:
        """Determine risk level and recommended action based on score."""
        thresholds = self.scoring_config.get("thresholds", {
            "allow": 0.0,
            "review": 0.30,
            "challenge": 0.60,
            "block": 0.80
        })
        
        if risk_score < thresholds["review"]:
            return "low", "allow"
        elif risk_score < thresholds["challenge"]:
            return "medium", "review"
        elif risk_score < thresholds["block"]:
            return "high", "challenge"
        else:
            return "critical", "block"
    
    def _calculate_confidence(self, num_rules: int, risk_score: float) -> float:
        """Calculate confidence in the risk score."""
        # More rules triggered = higher confidence
        # Higher score = higher confidence
        rule_confidence = min(1.0, num_rules / 3.0)  # Max 3 rules for full confidence
        score_confidence = risk_score
        
        return (rule_confidence + score_confidence) / 2
    
    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two coordinates in miles."""
        R = 3959  # Earth's radius in miles
        
        lat1_rad = radians(lat1)
        lon1_rad = radians(lon1)
        lat2_rad = radians(lat2)
        lon2_rad = radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = sin(dlat / 2) ** 2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2) ** 2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))
        
        return R * c
    
    async def _log_risk_decision(self, event: SentinelEvent, decision: RiskScore):
        """Log the risk decision with crypto-chaining for audit trail."""
        try:
            # Get previous log entry for crypto-chaining
            previous_entry = db_session.query(CryptoAuditLog).order_by(
                CryptoAuditLog.sequence.desc()
            ).first()
            
            previous_hash = previous_entry.current_hash if previous_entry else None
            
            # Create log entry
            log_entry = CryptoAuditLog(
                id=f"audit_{event.event_id}",
                event_id=event.event_id,
                event_type=event.event_type,
                user_id=event.actor.user_id,
                action="risk_score_calculated",
                decision=decision.recommended_action,
                risk_score=decision.risk_score,
                risk_level=decision.risk_level,
                previous_hash=previous_hash,
                log_data={
                    "risk_score": decision.risk_score,
                    "risk_level": decision.risk_level,
                    "triggered_rules": decision.triggered_rules,
                    "confidence": decision.confidence
                },
                actor_ip=event.actor.ip_address,
                actor_user_agent=event.actor.user_agent
            )
            
            # Calculate current hash
            log_str = json.dumps(log_entry.log_data, sort_keys=True, default=str)
            hash_input = f"{previous_hash or ''}{log_str}"
            log_entry.current_hash = hashlib.sha256(hash_input.encode()).hexdigest()
            
            db_session.add(log_entry)
            db_session.commit()
            
            logger.info(f"Logged risk decision: {event.event_id} -> {decision.recommended_action}")
            
        except Exception as e:
            logger.error(f"Error logging risk decision: {e}")
            db_session.rollback()
    
    def _evaluate_user_agent_anomaly(self, event: SentinelEvent) -> Dict[str, Any]:
        """
        Evaluate User-Agent for anomalies using Levenshtein distance.
        
        Detects subtle UA modifications that may indicate spoofing.
        """
        try:
            from app.services.ua_anomaly import check_ua_anomaly
            
            user_agent = event.actor.user_agent
            user_id = event.actor.user_id
            
            if not user_agent or not user_id:
                return {"is_anomaly": False, "score": 0.0}
            
            is_anomaly, score, reasons = check_ua_anomaly(
                user_id=user_id,
                user_agent=user_agent,
                session_id=event.context.session_id
            )
            
            if is_anomaly:
                logger.warning(
                    f"UA anomaly detected for user {user_id}: "
                    f"score={score:.2f}, reasons={reasons}"
                )
            
            return {
                "is_anomaly": is_anomaly,
                "score": score,
                "reasons": reasons
            }
            
        except ImportError:
            logger.debug("UA anomaly detection not available")
            return {"is_anomaly": False, "score": 0.0}
        except Exception as e:
            logger.error(f"UA anomaly detection error: {e}")
            return {"is_anomaly": False, "score": 0.0}
    
    async def _evaluate_ml_anomaly(self, event: SentinelEvent) -> Dict[str, Any]:
        """
        Evaluate event using ML Isolation Forest model.
        
        Returns ML-based anomaly score for ensemble with rule-based scoring.
        """
        try:
            from app.services.ml_engine import get_ml_engine
            from app.config import ML_ENABLED
            
            if not ML_ENABLED:
                return {"is_anomaly": False, "score": 0.0}
            
            ml_engine = get_ml_engine()
            
            # Build transaction dict from event
            transaction = {
                "amount": event.context.amount or 0,
                "timestamp": event.timestamp,
                "new_device": event.context.new_device,
                "new_ip": event.context.new_ip,
                "vpn_detected": event.context.proxy_detected,
                "country_risk": self._get_country_risk(event.context.country_code),
            }
            
            # Get user history for context
            user_history = self._get_user_history(event.actor.user_id)
            
            # Score transaction
            result = ml_engine.score_transaction(transaction, user_history)
            
            is_anomaly = result.get("is_ml_anomaly", False)
            score = result.get("ml_score", 0.0)
            
            if is_anomaly:
                logger.info(
                    f"ML anomaly detected for event {event.event_id}: "
                    f"score={score:.2f}, factors={result.get('top_risk_factors', [])}"
                )
            
            return {
                "is_anomaly": is_anomaly,
                "score": score,
                "factors": result.get("top_risk_factors", []),
                "model_version": result.get("model_version", "unknown")
            }
            
        except ImportError:
            logger.debug("ML engine not available")
            return {"is_anomaly": False, "score": 0.0}
        except Exception as e:
            logger.error(f"ML evaluation error: {e}")
            return {"is_anomaly": False, "score": 0.0}
    
    def _get_country_risk(self, country_code: Optional[str]) -> float:
        """Get risk score for a country."""
        if not country_code:
            return 0.3
        
        # High-risk countries (simplified - use proper list in production)
        high_risk = {"KP", "IR", "SY", "CU", "VE", "MM", "YE", "LY", "SO", "SD"}
        medium_risk = {"RU", "CN", "NG", "PK", "BD", "VN", "UA", "BY", "KZ"}
        
        if country_code.upper() in high_risk:
            return 0.9
        elif country_code.upper() in medium_risk:
            return 0.5
        else:
            return 0.1
    
    def _get_user_history(self, user_id: str) -> Dict[str, Any]:
        """Get user history for ML context."""
        try:
            # Get from Redis cache
            velocity = self.redis.get_velocity_counters(user_id)
            
            return {
                "transactions_1h": velocity.get("transactions_1h", 0),
                "transactions_24h": velocity.get("transactions_24h", 0),
                "avg_amount": velocity.get("avg_amount", 0),
                "std_amount": velocity.get("std_amount", 1),
                "distance_from_last": velocity.get("distance_from_last", 0)
            }
        except Exception:
            return {}


# Singleton instance
_risk_engine: Optional[RiskEngine] = None


def get_risk_engine() -> RiskEngine:
    """Get or create risk engine instance."""
    global _risk_engine
    if _risk_engine is None:
        _risk_engine = RiskEngine()
    return _risk_engine
