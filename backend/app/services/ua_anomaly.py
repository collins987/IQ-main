"""
User-Agent Anomaly Detection - Levenshtein Distance Analysis

Detects subtle User-Agent spoofing attempts using:
- Levenshtein (edit) distance comparison
- Historical User-Agent tracking per user
- Anomaly scoring for suspicious deviations

Attack Detection:
- Minor UA modifications (browser version tweaks)
- Device fingerprint masking attempts
- Bot detection through UA inconsistencies

Reference: Gap Analysis - Levenshtein Distance (MEDIUM priority)
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("sentineliq.ua_anomaly")


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate the Levenshtein (edit) distance between two strings.
    
    This is the minimum number of single-character edits
    (insertions, deletions, substitutions) required to transform
    one string into the other.
    
    Time Complexity: O(m * n) where m, n are string lengths
    Space Complexity: O(min(m, n)) using optimized rolling array
    """
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        
        for j, c2 in enumerate(s2):
            # Cost is 0 if characters match, 1 otherwise
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            
            current_row.append(min(insertions, deletions, substitutions))
        
        previous_row = current_row
    
    return previous_row[-1]


def normalized_similarity(s1: str, s2: str) -> float:
    """
    Calculate normalized similarity between two strings.
    
    Returns a value between 0.0 (completely different) and 1.0 (identical).
    """
    if not s1 and not s2:
        return 1.0
    
    if not s1 or not s2:
        return 0.0
    
    max_len = max(len(s1), len(s2))
    distance = levenshtein_distance(s1, s2)
    
    return 1.0 - (distance / max_len)


@dataclass
class ParsedUserAgent:
    """Parsed User-Agent components."""
    raw: str
    browser_family: Optional[str] = None
    browser_version: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None  # desktop, mobile, tablet, bot
    is_bot: bool = False
    
    @classmethod
    def parse(cls, user_agent: str) -> 'ParsedUserAgent':
        """Parse User-Agent string into components."""
        ua = user_agent.lower() if user_agent else ""
        parsed = cls(raw=user_agent or "")
        
        # Detect browser family
        if "chrome" in ua and "edg" not in ua:
            parsed.browser_family = "Chrome"
            match = re.search(r'chrome/(\d+\.?\d*)', ua)
            if match:
                parsed.browser_version = match.group(1)
        elif "firefox" in ua:
            parsed.browser_family = "Firefox"
            match = re.search(r'firefox/(\d+\.?\d*)', ua)
            if match:
                parsed.browser_version = match.group(1)
        elif "safari" in ua and "chrome" not in ua:
            parsed.browser_family = "Safari"
            match = re.search(r'version/(\d+\.?\d*)', ua)
            if match:
                parsed.browser_version = match.group(1)
        elif "edg" in ua:
            parsed.browser_family = "Edge"
            match = re.search(r'edg/(\d+\.?\d*)', ua)
            if match:
                parsed.browser_version = match.group(1)
        elif "msie" in ua or "trident" in ua:
            parsed.browser_family = "Internet Explorer"
        
        # Detect OS
        if "windows nt" in ua:
            parsed.os_family = "Windows"
            if "windows nt 10" in ua:
                parsed.os_version = "10"
            elif "windows nt 6.3" in ua:
                parsed.os_version = "8.1"
            elif "windows nt 6.1" in ua:
                parsed.os_version = "7"
        elif "mac os x" in ua:
            parsed.os_family = "macOS"
            match = re.search(r'mac os x (\d+[._]\d+)', ua)
            if match:
                parsed.os_version = match.group(1).replace("_", ".")
        elif "linux" in ua and "android" not in ua:
            parsed.os_family = "Linux"
        elif "android" in ua:
            parsed.os_family = "Android"
            match = re.search(r'android (\d+\.?\d*)', ua)
            if match:
                parsed.os_version = match.group(1)
        elif "iphone" in ua or "ipad" in ua:
            parsed.os_family = "iOS"
            match = re.search(r'os (\d+[._]\d+)', ua)
            if match:
                parsed.os_version = match.group(1).replace("_", ".")
        
        # Detect device type
        if any(bot in ua for bot in ["bot", "crawler", "spider", "crawl"]):
            parsed.device_type = "bot"
            parsed.is_bot = True
        elif "mobile" in ua or "android" in ua or "iphone" in ua:
            parsed.device_type = "mobile"
        elif "tablet" in ua or "ipad" in ua:
            parsed.device_type = "tablet"
        else:
            parsed.device_type = "desktop"
        
        return parsed


@dataclass
class UAHistoryEntry:
    """User-Agent history entry."""
    user_agent: str
    parsed: ParsedUserAgent
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    
    def update(self):
        """Update last seen and increment count."""
        self.last_seen = datetime.utcnow()
        self.count += 1


@dataclass
class UAComparisonResult:
    """Result of User-Agent comparison."""
    is_anomaly: bool
    anomaly_score: float  # 0.0 to 1.0
    similarity: float  # 0.0 to 1.0
    distance: int
    reasons: List[str] = field(default_factory=list)
    
    # Detailed component analysis
    browser_match: bool = True
    os_match: bool = True
    device_match: bool = True


class UserAgentAnomalyDetector:
    """
    Detects User-Agent anomalies using Levenshtein distance
    and component analysis.
    """
    
    def __init__(
        self,
        similarity_threshold: float = 0.85,
        version_drift_allowed: int = 3,
        history_window_days: int = 30
    ):
        """
        Initialize detector.
        
        Args:
            similarity_threshold: Minimum similarity to not be flagged
            version_drift_allowed: Allowed browser version difference
            history_window_days: How far back to check history
        """
        self.similarity_threshold = similarity_threshold
        self.version_drift_allowed = version_drift_allowed
        self.history_window_days = history_window_days
        
        # User history: user_id -> list of UA entries
        self.user_history: Dict[str, List[UAHistoryEntry]] = defaultdict(list)
        
        # Known bot patterns
        self.bot_patterns = [
            r"bot", r"crawler", r"spider", r"crawl", r"slurp",
            r"googlebot", r"bingbot", r"yandex", r"baidu",
            r"facebookexternalhit", r"linkedinbot", r"twitterbot"
        ]
    
    def analyze(
        self,
        user_id: str,
        current_ua: str,
        session_id: Optional[str] = None
    ) -> UAComparisonResult:
        """
        Analyze a User-Agent for anomalies.
        
        Compares against user's historical User-Agents
        using Levenshtein distance and component analysis.
        """
        parsed_current = ParsedUserAgent.parse(current_ua)
        
        # Get user's UA history
        history = self._get_recent_history(user_id)
        
        if not history:
            # First UA for this user - no comparison possible
            self._add_to_history(user_id, current_ua, parsed_current)
            return UAComparisonResult(
                is_anomaly=False,
                anomaly_score=0.0,
                similarity=1.0,
                distance=0,
                reasons=["first_user_agent"]
            )
        
        # Compare against each historical UA
        best_match = None
        best_similarity = 0.0
        anomaly_reasons = []
        
        for entry in history:
            similarity = normalized_similarity(current_ua, entry.user_agent)
            
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = entry
        
        if best_match is None:
            # Should not happen, but handle gracefully
            return UAComparisonResult(
                is_anomaly=False,
                anomaly_score=0.0,
                similarity=1.0,
                distance=0
            )
        
        # Detailed component comparison
        parsed_best = best_match.parsed
        distance = levenshtein_distance(current_ua, best_match.user_agent)
        
        browser_match = self._compare_browser(parsed_current, parsed_best)
        os_match = self._compare_os(parsed_current, parsed_best)
        device_match = parsed_current.device_type == parsed_best.device_type
        
        # Build anomaly reasons
        if not browser_match:
            anomaly_reasons.append(
                f"browser_changed: {parsed_best.browser_family} -> {parsed_current.browser_family}"
            )
        
        if not os_match:
            anomaly_reasons.append(
                f"os_changed: {parsed_best.os_family} -> {parsed_current.os_family}"
            )
        
        if not device_match:
            anomaly_reasons.append(
                f"device_changed: {parsed_best.device_type} -> {parsed_current.device_type}"
            )
        
        if best_similarity < self.similarity_threshold:
            anomaly_reasons.append(
                f"low_similarity: {best_similarity:.2%}"
            )
        
        # Check for suspicious patterns
        if self._is_suspicious_ua(current_ua, parsed_current):
            anomaly_reasons.append("suspicious_pattern")
        
        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly_score(
            best_similarity,
            browser_match,
            os_match,
            device_match,
            len(anomaly_reasons)
        )
        
        is_anomaly = anomaly_score >= 0.5
        
        # Update history if not anomalous
        if not is_anomaly:
            self._update_history(user_id, current_ua, parsed_current)
        
        result = UAComparisonResult(
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            similarity=best_similarity,
            distance=distance,
            reasons=anomaly_reasons,
            browser_match=browser_match,
            os_match=os_match,
            device_match=device_match
        )
        
        if is_anomaly:
            logger.warning(
                f"UA anomaly detected for user {user_id}: "
                f"score={anomaly_score:.2f}, reasons={anomaly_reasons}"
            )
        
        return result
    
    def _get_recent_history(self, user_id: str) -> List[UAHistoryEntry]:
        """Get recent UA history for user."""
        cutoff = datetime.utcnow() - timedelta(days=self.history_window_days)
        
        return [
            entry for entry in self.user_history[user_id]
            if entry.last_seen >= cutoff
        ]
    
    def _add_to_history(
        self,
        user_id: str,
        user_agent: str,
        parsed: ParsedUserAgent
    ):
        """Add new UA to history."""
        entry = UAHistoryEntry(
            user_agent=user_agent,
            parsed=parsed,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        self.user_history[user_id].append(entry)
        
        # Limit history size
        if len(self.user_history[user_id]) > 50:
            self.user_history[user_id] = self.user_history[user_id][-50:]
    
    def _update_history(
        self,
        user_id: str,
        user_agent: str,
        parsed: ParsedUserAgent
    ):
        """Update existing or add new UA to history."""
        for entry in self.user_history[user_id]:
            if entry.user_agent == user_agent:
                entry.update()
                return
        
        # Not found, add new
        self._add_to_history(user_id, user_agent, parsed)
    
    def _compare_browser(
        self,
        current: ParsedUserAgent,
        historical: ParsedUserAgent
    ) -> bool:
        """Compare browser with allowed version drift."""
        if current.browser_family != historical.browser_family:
            return False
        
        # Check version drift
        if current.browser_version and historical.browser_version:
            try:
                current_major = int(current.browser_version.split(".")[0])
                historical_major = int(historical.browser_version.split(".")[0])
                
                if abs(current_major - historical_major) > self.version_drift_allowed:
                    return False
            except (ValueError, IndexError):
                pass
        
        return True
    
    def _compare_os(
        self,
        current: ParsedUserAgent,
        historical: ParsedUserAgent
    ) -> bool:
        """Compare OS."""
        return current.os_family == historical.os_family
    
    def _is_suspicious_ua(
        self,
        user_agent: str,
        parsed: ParsedUserAgent
    ) -> bool:
        """Detect suspicious UA patterns."""
        ua_lower = user_agent.lower()
        
        # Empty or very short UA
        if len(user_agent) < 10:
            return True
        
        # Known automation tools
        suspicious_patterns = [
            "headless", "phantom", "selenium", "puppeteer",
            "webdriver", "cypress", "playwright"
        ]
        
        if any(pattern in ua_lower for pattern in suspicious_patterns):
            return True
        
        # User claims to be mobile but uses desktop keywords
        if parsed.device_type == "mobile":
            desktop_keywords = ["windows nt", "macintosh", "x11"]
            if any(kw in ua_lower for kw in desktop_keywords):
                return True
        
        # Inconsistent UA (claims multiple browsers)
        browser_keywords = ["chrome", "firefox", "safari", "edge"]
        browser_count = sum(1 for kw in browser_keywords if kw in ua_lower)
        if browser_count > 2:  # Chrome/Safari often both appear
            return True
        
        return False
    
    def _calculate_anomaly_score(
        self,
        similarity: float,
        browser_match: bool,
        os_match: bool,
        device_match: bool,
        reason_count: int
    ) -> float:
        """Calculate overall anomaly score."""
        score = 0.0
        
        # Similarity contributes most
        if similarity < self.similarity_threshold:
            score += 0.4 * (1 - similarity / self.similarity_threshold)
        
        # Component mismatches
        if not browser_match:
            score += 0.2
        
        if not os_match:
            score += 0.15
        
        if not device_match:
            score += 0.25
        
        # Additional reasons
        score += 0.05 * min(reason_count, 4)
        
        return min(score, 1.0)
    
    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Get UA profile for a user."""
        history = self._get_recent_history(user_id)
        
        if not history:
            return {"user_id": user_id, "has_history": False}
        
        browsers = set()
        operating_systems = set()
        devices = set()
        
        for entry in history:
            if entry.parsed.browser_family:
                browsers.add(entry.parsed.browser_family)
            if entry.parsed.os_family:
                operating_systems.add(entry.parsed.os_family)
            if entry.parsed.device_type:
                devices.add(entry.parsed.device_type)
        
        return {
            "user_id": user_id,
            "has_history": True,
            "ua_count": len(history),
            "browsers": list(browsers),
            "operating_systems": list(operating_systems),
            "devices": list(devices),
            "first_seen": min(e.first_seen for e in history).isoformat(),
            "last_seen": max(e.last_seen for e in history).isoformat()
        }


# Global detector instance
_detector: Optional[UserAgentAnomalyDetector] = None


def get_ua_detector() -> UserAgentAnomalyDetector:
    """Get or create UA detector singleton."""
    global _detector
    if _detector is None:
        _detector = UserAgentAnomalyDetector()
    return _detector


# Convenience function for risk engine integration
def check_ua_anomaly(
    user_id: str,
    user_agent: str,
    session_id: Optional[str] = None
) -> Tuple[bool, float, List[str]]:
    """
    Check User-Agent for anomalies.
    
    Returns:
        Tuple of (is_anomaly, anomaly_score, reasons)
    """
    detector = get_ua_detector()
    result = detector.analyze(user_id, user_agent, session_id)
    
    return result.is_anomaly, result.anomaly_score, result.reasons


__all__ = [
    'UserAgentAnomalyDetector',
    'ParsedUserAgent',
    'UAComparisonResult',
    'levenshtein_distance',
    'normalized_similarity',
    'get_ua_detector',
    'check_ua_anomaly'
]
