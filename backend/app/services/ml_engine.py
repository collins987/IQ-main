"""
Machine Learning Integration - Isolation Forest Anomaly Detection

Implements ML-based fraud detection using:
- Isolation Forest for unsupervised anomaly detection
- Feature engineering for transaction patterns
- Real-time scoring with batch model updates
- Explainability through feature importance

Model Lifecycle:
- Batch training on historical data (daily/weekly)
- Real-time inference via pre-loaded model
- A/B testing support for model versions

Reference: Gap Analysis - ML Integration (MEDIUM priority)
"""

import logging
import pickle
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import json

import numpy as np

logger = logging.getLogger("sentineliq.ml_engine")

# Try to import sklearn (optional dependency)
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not installed. ML features will be disabled.")


@dataclass
class FeatureConfig:
    """Configuration for a feature."""
    name: str
    description: str
    dtype: str  # "numeric", "categorical", "boolean"
    default_value: Any = 0
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    categories: List[str] = field(default_factory=list)


# Feature definitions for fraud detection
FEATURE_DEFINITIONS = [
    FeatureConfig(
        name="amount",
        description="Transaction amount in dollars",
        dtype="numeric",
        default_value=0,
        min_value=0,
        max_value=1000000
    ),
    FeatureConfig(
        name="hour_of_day",
        description="Hour when transaction occurred (0-23)",
        dtype="numeric",
        default_value=12,
        min_value=0,
        max_value=23
    ),
    FeatureConfig(
        name="day_of_week",
        description="Day of week (0=Monday, 6=Sunday)",
        dtype="numeric",
        default_value=0,
        min_value=0,
        max_value=6
    ),
    FeatureConfig(
        name="is_weekend",
        description="Whether transaction is on weekend",
        dtype="boolean",
        default_value=False
    ),
    FeatureConfig(
        name="is_night",
        description="Whether transaction is at night (11PM-5AM)",
        dtype="boolean",
        default_value=False
    ),
    FeatureConfig(
        name="velocity_1h",
        description="Number of transactions in last hour",
        dtype="numeric",
        default_value=0,
        min_value=0
    ),
    FeatureConfig(
        name="velocity_24h",
        description="Number of transactions in last 24 hours",
        dtype="numeric",
        default_value=0,
        min_value=0
    ),
    FeatureConfig(
        name="amount_zscore",
        description="Z-score of amount vs user history",
        dtype="numeric",
        default_value=0
    ),
    FeatureConfig(
        name="distance_from_last",
        description="Distance in km from last transaction location",
        dtype="numeric",
        default_value=0,
        min_value=0
    ),
    FeatureConfig(
        name="new_device",
        description="Whether device is new for user",
        dtype="boolean",
        default_value=False
    ),
    FeatureConfig(
        name="new_ip",
        description="Whether IP is new for user",
        dtype="boolean",
        default_value=False
    ),
    FeatureConfig(
        name="failed_attempts_recent",
        description="Failed auth attempts in last hour",
        dtype="numeric",
        default_value=0,
        min_value=0
    ),
    FeatureConfig(
        name="merchant_risk_score",
        description="Risk score of merchant (0-1)",
        dtype="numeric",
        default_value=0.1,
        min_value=0,
        max_value=1
    ),
    FeatureConfig(
        name="country_risk_score",
        description="Risk score of transaction country",
        dtype="numeric",
        default_value=0.1,
        min_value=0,
        max_value=1
    ),
    FeatureConfig(
        name="vpn_detected",
        description="Whether VPN/proxy detected",
        dtype="boolean",
        default_value=False
    )
]

FEATURE_NAMES = [f.name for f in FEATURE_DEFINITIONS]


@dataclass
class MLPrediction:
    """ML model prediction result."""
    is_anomaly: bool
    anomaly_score: float  # 0 to 1 (higher = more anomalous)
    confidence: float  # Model confidence
    top_features: List[Tuple[str, float]]  # (feature_name, contribution)
    model_version: str
    inference_time_ms: float


class FeatureEngineering:
    """Feature extraction and transformation."""
    
    def __init__(self):
        self.feature_configs = {f.name: f for f in FEATURE_DEFINITIONS}
    
    def extract_features(
        self,
        transaction: Dict[str, Any],
        user_history: Optional[Dict[str, Any]] = None
    ) -> Dict[str, float]:
        """
        Extract features from a transaction.
        
        Args:
            transaction: Transaction data
            user_history: Historical data for the user
            
        Returns:
            Dictionary of feature name -> value
        """
        features = {}
        
        # Basic amount
        features["amount"] = float(transaction.get("amount", 0))
        
        # Time-based features
        timestamp = transaction.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.utcnow()
        
        features["hour_of_day"] = timestamp.hour
        features["day_of_week"] = timestamp.weekday()
        features["is_weekend"] = 1.0 if timestamp.weekday() >= 5 else 0.0
        features["is_night"] = 1.0 if timestamp.hour >= 23 or timestamp.hour < 5 else 0.0
        
        # Velocity features (from user history)
        if user_history:
            features["velocity_1h"] = float(user_history.get("transactions_1h", 0))
            features["velocity_24h"] = float(user_history.get("transactions_24h", 0))
            
            # Amount z-score
            avg_amount = user_history.get("avg_amount", features["amount"])
            std_amount = user_history.get("std_amount", 1)
            if std_amount > 0:
                features["amount_zscore"] = (features["amount"] - avg_amount) / std_amount
            else:
                features["amount_zscore"] = 0
            
            # Distance from last transaction
            features["distance_from_last"] = float(user_history.get("distance_from_last", 0))
        else:
            features["velocity_1h"] = 0
            features["velocity_24h"] = 0
            features["amount_zscore"] = 0
            features["distance_from_last"] = 0
        
        # Device/IP features
        features["new_device"] = 1.0 if transaction.get("new_device", False) else 0.0
        features["new_ip"] = 1.0 if transaction.get("new_ip", False) else 0.0
        features["failed_attempts_recent"] = float(transaction.get("failed_attempts", 0))
        
        # Risk scores
        features["merchant_risk_score"] = float(transaction.get("merchant_risk", 0.1))
        features["country_risk_score"] = float(transaction.get("country_risk", 0.1))
        features["vpn_detected"] = 1.0 if transaction.get("vpn_detected", False) else 0.0
        
        return features
    
    def features_to_array(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dict to numpy array in correct order."""
        return np.array([[features.get(name, 0) for name in FEATURE_NAMES]])
    
    def validate_features(self, features: Dict[str, float]) -> List[str]:
        """Validate feature values and return any warnings."""
        warnings = []
        
        for name, value in features.items():
            config = self.feature_configs.get(name)
            if not config:
                continue
            
            if config.min_value is not None and value < config.min_value:
                warnings.append(f"{name} below minimum: {value} < {config.min_value}")
            
            if config.max_value is not None and value > config.max_value:
                warnings.append(f"{name} above maximum: {value} > {config.max_value}")
        
        return warnings


class IsolationForestModel:
    """
    Isolation Forest model for anomaly detection.
    
    Isolation Forest works by:
    1. Building ensemble of isolation trees
    2. Each tree isolates observations by random feature splits
    3. Anomalies require fewer splits to isolate (shorter path)
    4. Anomaly score = average path length across trees
    """
    
    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        max_samples: int = 256,
        random_state: int = 42
    ):
        """
        Initialize Isolation Forest model.
        
        Args:
            contamination: Expected proportion of anomalies (0.1 = 10%)
            n_estimators: Number of trees in the forest
            max_samples: Samples to train each tree
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        
        self.model = None
        self.scaler = None
        self.feature_names = FEATURE_NAMES
        self.version = "untrained"
        self.trained_at = None
        self.training_samples = 0
        
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                contamination=contamination,
                n_estimators=n_estimators,
                max_samples=max_samples,
                random_state=random_state,
                n_jobs=-1  # Use all cores
            )
            self.scaler = StandardScaler()
    
    def train(
        self,
        training_data: List[Dict[str, float]],
        version: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Train the model on historical data.
        
        Args:
            training_data: List of feature dictionaries
            version: Model version identifier
            
        Returns:
            Training metrics
        """
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available"}
        
        if len(training_data) < 100:
            return {"error": "Insufficient training data (need 100+ samples)"}
        
        # Convert to numpy array
        feature_engineering = FeatureEngineering()
        X = np.array([
            [d.get(name, 0) for name in self.feature_names]
            for d in training_data
        ])
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        start_time = datetime.utcnow()
        self.model.fit(X_scaled)
        training_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Update metadata
        self.version = version or f"v{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.trained_at = datetime.utcnow()
        self.training_samples = len(training_data)
        
        # Calculate training metrics
        predictions = self.model.predict(X_scaled)
        anomaly_count = np.sum(predictions == -1)
        
        logger.info(
            f"Model trained: version={self.version}, "
            f"samples={self.training_samples}, "
            f"anomalies={anomaly_count}"
        )
        
        return {
            "version": self.version,
            "training_samples": self.training_samples,
            "training_time_seconds": training_time,
            "anomaly_rate": anomaly_count / len(training_data),
            "features": self.feature_names
        }
    
    def predict(
        self,
        features: Dict[str, float]
    ) -> MLPrediction:
        """
        Make a prediction for a single transaction.
        
        Args:
            features: Feature dictionary
            
        Returns:
            MLPrediction with anomaly score and details
        """
        start_time = datetime.utcnow()
        
        if not SKLEARN_AVAILABLE or self.model is None:
            # Fallback: simple rule-based scoring
            return self._fallback_predict(features)
        
        # Convert to array and scale
        X = np.array([[features.get(name, 0) for name in self.feature_names]])
        
        try:
            X_scaled = self.scaler.transform(X)
        except Exception:
            # Scaler not fitted, use raw values
            X_scaled = X
        
        # Get prediction and anomaly score
        # decision_function returns negative for anomalies
        raw_score = self.model.decision_function(X_scaled)[0]
        prediction = self.model.predict(X_scaled)[0]
        
        # Convert to 0-1 score (higher = more anomalous)
        # Raw score is typically in [-0.5, 0.5], anomalies have negative scores
        anomaly_score = max(0, min(1, 0.5 - raw_score))
        
        # Calculate feature contributions (approximate)
        top_features = self._calculate_feature_importance(features, X_scaled)
        
        inference_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return MLPrediction(
            is_anomaly=(prediction == -1),
            anomaly_score=anomaly_score,
            confidence=min(0.95, 0.5 + abs(raw_score)),
            top_features=top_features,
            model_version=self.version,
            inference_time_ms=inference_time
        )
    
    def _fallback_predict(self, features: Dict[str, float]) -> MLPrediction:
        """Simple rule-based fallback when ML is unavailable."""
        score = 0.0
        reasons = []
        
        # High amount
        if features.get("amount", 0) > 5000:
            score += 0.2
            reasons.append(("amount", 0.2))
        
        # Night transaction
        if features.get("is_night", 0) == 1:
            score += 0.1
            reasons.append(("is_night", 0.1))
        
        # High velocity
        if features.get("velocity_1h", 0) > 5:
            score += 0.15
            reasons.append(("velocity_1h", 0.15))
        
        # New device
        if features.get("new_device", 0) == 1:
            score += 0.15
            reasons.append(("new_device", 0.15))
        
        # VPN detected
        if features.get("vpn_detected", 0) == 1:
            score += 0.2
            reasons.append(("vpn_detected", 0.2))
        
        # High amount z-score
        if abs(features.get("amount_zscore", 0)) > 2:
            score += 0.2
            reasons.append(("amount_zscore", 0.2))
        
        return MLPrediction(
            is_anomaly=(score >= 0.5),
            anomaly_score=min(score, 1.0),
            confidence=0.6,
            top_features=reasons[:5],
            model_version="fallback_rules",
            inference_time_ms=0.1
        )
    
    def _calculate_feature_importance(
        self,
        features: Dict[str, float],
        X_scaled: np.ndarray
    ) -> List[Tuple[str, float]]:
        """
        Calculate approximate feature importance for this prediction.
        
        Uses perturbation-based importance estimation.
        """
        importances = []
        base_score = self.model.decision_function(X_scaled)[0]
        
        for i, name in enumerate(self.feature_names):
            # Perturb feature to zero
            X_perturbed = X_scaled.copy()
            X_perturbed[0, i] = 0
            
            perturbed_score = self.model.decision_function(X_perturbed)[0]
            importance = abs(base_score - perturbed_score)
            importances.append((name, importance))
        
        # Sort by importance and return top 5
        importances.sort(key=lambda x: x[1], reverse=True)
        return importances[:5]
    
    def save(self, path: str):
        """Save model to disk."""
        if not SKLEARN_AVAILABLE:
            logger.error("Cannot save: scikit-learn not available")
            return
        
        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "version": self.version,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "training_samples": self.training_samples,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators
        }
        
        with open(path, "wb") as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Model saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'IsolationForestModel':
        """Load model from disk."""
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn not available")
        
        with open(path, "rb") as f:
            model_data = pickle.load(f)
        
        instance = cls(
            contamination=model_data.get("contamination", 0.1),
            n_estimators=model_data.get("n_estimators", 100)
        )
        
        instance.model = model_data["model"]
        instance.scaler = model_data["scaler"]
        instance.feature_names = model_data["feature_names"]
        instance.version = model_data["version"]
        instance.trained_at = (
            datetime.fromisoformat(model_data["trained_at"])
            if model_data.get("trained_at") else None
        )
        instance.training_samples = model_data.get("training_samples", 0)
        
        logger.info(f"Model loaded: version={instance.version}")
        return instance


class MLFraudEngine:
    """
    High-level ML fraud detection engine.
    
    Manages model lifecycle and provides scoring API.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize ML engine with optional pre-trained model."""
        self.feature_engineering = FeatureEngineering()
        self.model = IsolationForestModel()
        self.model_path = model_path or "models/fraud_model.pkl"
        
        # Try to load existing model
        if Path(self.model_path).exists():
            try:
                self.model = IsolationForestModel.load(self.model_path)
            except Exception as e:
                logger.warning(f"Could not load model: {e}")
    
    def score_transaction(
        self,
        transaction: Dict[str, Any],
        user_history: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Score a transaction for fraud probability.
        
        Args:
            transaction: Transaction data
            user_history: User's historical data
            
        Returns:
            Scoring result with ML insights
        """
        # Extract features
        features = self.feature_engineering.extract_features(
            transaction, user_history
        )
        
        # Validate features
        warnings = self.feature_engineering.validate_features(features)
        
        # Get ML prediction
        prediction = self.model.predict(features)
        
        return {
            "ml_score": prediction.anomaly_score,
            "is_ml_anomaly": prediction.is_anomaly,
            "confidence": prediction.confidence,
            "top_risk_factors": [
                {"feature": name, "contribution": score}
                for name, score in prediction.top_features
            ],
            "model_version": prediction.model_version,
            "inference_time_ms": prediction.inference_time_ms,
            "warnings": warnings
        }
    
    def train_model(
        self,
        training_data: List[Dict[str, Any]],
        save: bool = True
    ) -> Dict[str, Any]:
        """
        Train or retrain the model.
        
        Args:
            training_data: Historical transaction data
            save: Whether to save the model after training
            
        Returns:
            Training metrics
        """
        # Extract features for all transactions
        feature_data = [
            self.feature_engineering.extract_features(tx)
            for tx in training_data
        ]
        
        # Train model
        metrics = self.model.train(feature_data)
        
        # Save if requested
        if save and "error" not in metrics:
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            self.model.save(self.model_path)
        
        return metrics
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            "version": self.model.version,
            "trained_at": self.model.trained_at.isoformat() if self.model.trained_at else None,
            "training_samples": self.model.training_samples,
            "features": self.model.feature_names,
            "sklearn_available": SKLEARN_AVAILABLE,
            "model_path": self.model_path
        }


# Global ML engine instance
_ml_engine: Optional[MLFraudEngine] = None


def get_ml_engine() -> MLFraudEngine:
    """Get or create ML engine singleton."""
    global _ml_engine
    if _ml_engine is None:
        _ml_engine = MLFraudEngine()
    return _ml_engine


__all__ = [
    'MLFraudEngine',
    'IsolationForestModel',
    'FeatureEngineering',
    'MLPrediction',
    'FEATURE_DEFINITIONS',
    'get_ml_engine'
]
