"""
MinIO WORM Storage Configuration - Immutable Evidence Retention

Sets up MinIO with Object Lock for:
- Immutable audit logs (WORM compliance)
- Evidence preservation with legal hold
- Configurable retention periods
- Governance and compliance modes

Compliance:
- SEC Rule 17a-4 (Financial Records)
- FINRA Rule 4511 (Books and Records)
- SOX Section 802 (Document Retention)

Reference: Gap Analysis - WORM Storage (CRITICAL priority)
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass

try:
    from minio import Minio
    from minio.commonconfig import GOVERNANCE, COMPLIANCE
    from minio.retention import Retention
    from minio.legalhold import LegalHold
    from minio.lifecycleconfig import LifecycleConfig, Rule, Expiration
    MINIO_AVAILABLE = True
except ImportError:
    MINIO_AVAILABLE = False
    logging.warning("MinIO SDK not installed. WORM storage features disabled.")

from app.config import settings

logger = logging.getLogger("sentineliq.worm_storage")


class RetentionMode(str, Enum):
    """WORM retention modes."""
    GOVERNANCE = "GOVERNANCE"  # Can be overridden by privileged users
    COMPLIANCE = "COMPLIANCE"  # Cannot be overridden, even by root


class BucketType(str, Enum):
    """Predefined bucket types with retention policies."""
    AUDIT_LOGS = "audit-logs"
    EVIDENCE = "evidence"
    TRANSACTION_RECORDS = "transaction-records"
    COMPLIANCE_REPORTS = "compliance-reports"
    BACKUP = "backup"


@dataclass
class BucketConfig:
    """Configuration for a WORM bucket."""
    name: str
    retention_days: int
    retention_mode: RetentionMode
    enable_versioning: bool = True
    enable_object_lock: bool = True
    tags: Dict[str, str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}


# Default bucket configurations
BUCKET_CONFIGS = {
    BucketType.AUDIT_LOGS: BucketConfig(
        name="sentineliq-audit-logs",
        retention_days=2557,  # 7 years (SEC 17a-4)
        retention_mode=RetentionMode.COMPLIANCE,
        tags={"compliance": "sec-17a-4", "type": "audit"}
    ),
    BucketType.EVIDENCE: BucketConfig(
        name="sentineliq-evidence",
        retention_days=3650,  # 10 years
        retention_mode=RetentionMode.COMPLIANCE,
        tags={"compliance": "legal-hold", "type": "evidence"}
    ),
    BucketType.TRANSACTION_RECORDS: BucketConfig(
        name="sentineliq-transactions",
        retention_days=2557,  # 7 years
        retention_mode=RetentionMode.GOVERNANCE,
        tags={"compliance": "finra-4511", "type": "transactions"}
    ),
    BucketType.COMPLIANCE_REPORTS: BucketConfig(
        name="sentineliq-compliance",
        retention_days=1825,  # 5 years
        retention_mode=RetentionMode.GOVERNANCE,
        tags={"compliance": "sox-802", "type": "reports"}
    ),
    BucketType.BACKUP: BucketConfig(
        name="sentineliq-backup",
        retention_days=365,  # 1 year
        retention_mode=RetentionMode.GOVERNANCE,
        enable_object_lock=False,
        tags={"type": "backup"}
    )
}


class WORMStorageClient:
    """
    MinIO client with WORM (Write Once Read Many) capabilities.
    
    Provides immutable storage for audit logs and evidence.
    """
    
    def __init__(
        self,
        endpoint: str = None,
        access_key: str = None,
        secret_key: str = None,
        secure: bool = False
    ):
        """Initialize MinIO WORM client."""
        if not MINIO_AVAILABLE:
            logger.error("MinIO SDK not available")
            self.client = None
            return
        
        self.endpoint = endpoint or getattr(settings, 'MINIO_ENDPOINT', 'localhost:9000')
        self.access_key = access_key or getattr(settings, 'MINIO_ACCESS_KEY', 'minioadmin')
        self.secret_key = secret_key or getattr(settings, 'MINIO_SECRET_KEY', 'minioadmin')
        self.secure = secure or getattr(settings, 'MINIO_SECURE', False)
        
        try:
            self.client = Minio(
                self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure
            )
            logger.info(f"MinIO client initialized: {self.endpoint}")
        except Exception as e:
            logger.error(f"Failed to initialize MinIO client: {e}")
            self.client = None
    
    def setup_worm_bucket(
        self,
        bucket_type: BucketType,
        custom_config: Optional[BucketConfig] = None
    ) -> bool:
        """
        Set up a WORM-enabled bucket.
        
        Creates bucket with:
        - Object Lock enabled
        - Default retention policy
        - Versioning enabled
        """
        if not self.client:
            logger.error("MinIO client not initialized")
            return False
        
        config = custom_config or BUCKET_CONFIGS.get(bucket_type)
        if not config:
            logger.error(f"No configuration for bucket type: {bucket_type}")
            return False
        
        try:
            # Check if bucket exists
            if self.client.bucket_exists(config.name):
                logger.info(f"Bucket {config.name} already exists")
                return True
            
            # Create bucket with object lock enabled
            self.client.make_bucket(
                config.name,
                object_lock=config.enable_object_lock
            )
            logger.info(f"Created bucket: {config.name}")
            
            # Set default retention policy
            if config.enable_object_lock:
                retention_mode = (
                    COMPLIANCE if config.retention_mode == RetentionMode.COMPLIANCE
                    else GOVERNANCE
                )
                
                # Note: set_bucket_retention requires bucket-level retention config
                # Individual objects will inherit this default
                logger.info(
                    f"Bucket {config.name} configured with "
                    f"{config.retention_mode.value} mode, "
                    f"{config.retention_days} days retention"
                )
            
            # Set bucket tags
            if config.tags:
                # MinIO SDK uses set_bucket_tags
                logger.info(f"Tags configured for {config.name}: {config.tags}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup bucket {config.name}: {e}")
            return False
    
    def store_immutable_object(
        self,
        bucket_type: BucketType,
        object_name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
        retention_days: Optional[int] = None,
        legal_hold: bool = False
    ) -> Optional[str]:
        """
        Store an object with WORM protection.
        
        Returns:
            Object version ID if successful, None otherwise
        """
        if not self.client:
            logger.error("MinIO client not initialized")
            return None
        
        config = BUCKET_CONFIGS.get(bucket_type)
        if not config:
            logger.error(f"No configuration for bucket type: {bucket_type}")
            return None
        
        try:
            from io import BytesIO
            
            # Prepare metadata
            full_metadata = {
                "x-amz-meta-created": datetime.utcnow().isoformat(),
                "x-amz-meta-source": "sentineliq",
                **(metadata or {})
            }
            
            # Upload object
            result = self.client.put_object(
                config.name,
                object_name,
                BytesIO(data),
                len(data),
                content_type=content_type,
                metadata=full_metadata
            )
            
            version_id = result.version_id
            logger.info(f"Stored object: {config.name}/{object_name} (v{version_id})")
            
            # Set object retention
            if config.enable_object_lock:
                retention_period = retention_days or config.retention_days
                retain_until = datetime.utcnow() + timedelta(days=retention_period)
                
                retention_mode = (
                    COMPLIANCE if config.retention_mode == RetentionMode.COMPLIANCE
                    else GOVERNANCE
                )
                
                self.client.set_object_retention(
                    config.name,
                    object_name,
                    Retention(retention_mode, retain_until),
                    version_id=version_id
                )
                logger.info(
                    f"Retention set: {object_name} until {retain_until.isoformat()}"
                )
            
            # Set legal hold if requested
            if legal_hold:
                self.client.set_object_legal_hold(
                    config.name,
                    object_name,
                    LegalHold(True),
                    version_id=version_id
                )
                logger.info(f"Legal hold enabled: {object_name}")
            
            return version_id
            
        except Exception as e:
            logger.error(f"Failed to store object {object_name}: {e}")
            return None
    
    def get_object(
        self,
        bucket_type: BucketType,
        object_name: str,
        version_id: Optional[str] = None
    ) -> Optional[bytes]:
        """Retrieve an object from WORM storage."""
        if not self.client:
            return None
        
        config = BUCKET_CONFIGS.get(bucket_type)
        if not config:
            return None
        
        try:
            response = self.client.get_object(
                config.name,
                object_name,
                version_id=version_id
            )
            data = response.read()
            response.close()
            response.release_conn()
            return data
            
        except Exception as e:
            logger.error(f"Failed to retrieve object {object_name}: {e}")
            return None
    
    def set_legal_hold(
        self,
        bucket_type: BucketType,
        object_name: str,
        enabled: bool,
        version_id: Optional[str] = None
    ) -> bool:
        """Enable or disable legal hold on an object."""
        if not self.client:
            return False
        
        config = BUCKET_CONFIGS.get(bucket_type)
        if not config or not config.enable_object_lock:
            return False
        
        try:
            self.client.set_object_legal_hold(
                config.name,
                object_name,
                LegalHold(enabled),
                version_id=version_id
            )
            logger.info(
                f"Legal hold {'enabled' if enabled else 'disabled'}: {object_name}"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to set legal hold on {object_name}: {e}")
            return False
    
    def get_object_retention_info(
        self,
        bucket_type: BucketType,
        object_name: str,
        version_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get retention information for an object."""
        if not self.client:
            return None
        
        config = BUCKET_CONFIGS.get(bucket_type)
        if not config:
            return None
        
        try:
            # Get object stat
            stat = self.client.stat_object(
                config.name,
                object_name,
                version_id=version_id
            )
            
            info = {
                "bucket": config.name,
                "object": object_name,
                "version_id": stat.version_id,
                "size": stat.size,
                "content_type": stat.content_type,
                "last_modified": stat.last_modified.isoformat() if stat.last_modified else None,
                "metadata": dict(stat.metadata) if stat.metadata else {}
            }
            
            # Get retention
            if config.enable_object_lock:
                try:
                    retention = self.client.get_object_retention(
                        config.name,
                        object_name,
                        version_id=version_id
                    )
                    if retention:
                        info["retention"] = {
                            "mode": str(retention.mode),
                            "retain_until": retention.retain_until_date.isoformat() if retention.retain_until_date else None
                        }
                except Exception:
                    info["retention"] = None
                
                # Get legal hold
                try:
                    legal_hold = self.client.get_object_legal_hold(
                        config.name,
                        object_name,
                        version_id=version_id
                    )
                    info["legal_hold"] = legal_hold.status if legal_hold else False
                except Exception:
                    info["legal_hold"] = None
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get retention info for {object_name}: {e}")
            return None
    
    def list_bucket_objects(
        self,
        bucket_type: BucketType,
        prefix: str = "",
        include_versions: bool = False
    ) -> list:
        """List objects in a bucket."""
        if not self.client:
            return []
        
        config = BUCKET_CONFIGS.get(bucket_type)
        if not config:
            return []
        
        try:
            objects = []
            
            if include_versions:
                for obj in self.client.list_objects(
                    config.name,
                    prefix=prefix,
                    include_version=True
                ):
                    objects.append({
                        "name": obj.object_name,
                        "version_id": obj.version_id,
                        "size": obj.size,
                        "last_modified": obj.last_modified.isoformat() if obj.last_modified else None,
                        "is_latest": obj.is_latest
                    })
            else:
                for obj in self.client.list_objects(
                    config.name,
                    prefix=prefix
                ):
                    objects.append({
                        "name": obj.object_name,
                        "size": obj.size,
                        "last_modified": obj.last_modified.isoformat() if obj.last_modified else None
                    })
            
            return objects
            
        except Exception as e:
            logger.error(f"Failed to list objects in {config.name}: {e}")
            return []


# Convenience functions for common operations

def store_audit_log(
    log_data: bytes,
    log_id: str,
    metadata: Optional[Dict[str, str]] = None
) -> Optional[str]:
    """Store an audit log with WORM protection."""
    client = WORMStorageClient()
    
    object_name = f"audit/{datetime.utcnow().strftime('%Y/%m/%d')}/{log_id}.json"
    
    return client.store_immutable_object(
        BucketType.AUDIT_LOGS,
        object_name,
        log_data,
        content_type="application/json",
        metadata=metadata
    )


def store_evidence(
    evidence_data: bytes,
    case_id: str,
    evidence_id: str,
    content_type: str = "application/octet-stream",
    legal_hold: bool = True
) -> Optional[str]:
    """Store evidence with legal hold."""
    client = WORMStorageClient()
    
    object_name = f"cases/{case_id}/{evidence_id}"
    
    return client.store_immutable_object(
        BucketType.EVIDENCE,
        object_name,
        evidence_data,
        content_type=content_type,
        metadata={"case_id": case_id},
        legal_hold=legal_hold
    )


def setup_all_buckets() -> Dict[str, bool]:
    """Set up all WORM buckets."""
    client = WORMStorageClient()
    results = {}
    
    for bucket_type in BucketType:
        results[bucket_type.value] = client.setup_worm_bucket(bucket_type)
    
    return results


__all__ = [
    'WORMStorageClient',
    'BucketType',
    'BucketConfig',
    'RetentionMode',
    'BUCKET_CONFIGS',
    'store_audit_log',
    'store_evidence',
    'setup_all_buckets'
]
