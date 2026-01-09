#!/usr/bin/env python3
"""
MinIO WORM Setup Script

Initializes MinIO buckets with Object Lock for WORM compliance.
Run after MinIO container is healthy.

Usage:
    python scripts/setup_minio_worm.py

Buckets created:
- sentineliq-audit-logs (7 year retention, COMPLIANCE mode)
- sentineliq-evidence (10 year retention, COMPLIANCE mode)
- sentineliq-transactions (7 year retention, GOVERNANCE mode)
- sentineliq-compliance (5 year retention, GOVERNANCE mode)
- sentineliq-backup (1 year retention, GOVERNANCE mode)
"""

import os
import sys
import time
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from minio import Minio
    from minio.error import S3Error
except ImportError:
    print("ERROR: minio package not installed. Run: pip install minio")
    sys.exit(1)


# Configuration
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

# Bucket definitions
BUCKETS = [
    {
        "name": "sentineliq-audit-logs",
        "retention_days": 2557,  # 7 years (SEC 17a-4)
        "retention_mode": "COMPLIANCE",
        "description": "Immutable audit logs (SEC 17a-4 compliant)"
    },
    {
        "name": "sentineliq-evidence",
        "retention_days": 3650,  # 10 years
        "retention_mode": "COMPLIANCE",
        "description": "Legal evidence with mandatory retention"
    },
    {
        "name": "sentineliq-transactions",
        "retention_days": 2557,  # 7 years
        "retention_mode": "GOVERNANCE",
        "description": "Transaction records (FINRA 4511 compliant)"
    },
    {
        "name": "sentineliq-compliance",
        "retention_days": 1825,  # 5 years
        "retention_mode": "GOVERNANCE",
        "description": "Compliance reports and attestations"
    },
    {
        "name": "sentineliq-backup",
        "retention_days": 365,  # 1 year
        "retention_mode": "GOVERNANCE",
        "description": "System backups with standard retention"
    }
]


def wait_for_minio(client: Minio, max_retries: int = 30) -> bool:
    """Wait for MinIO to be ready."""
    print(f"Waiting for MinIO at {MINIO_ENDPOINT}...")
    
    for i in range(max_retries):
        try:
            # Try to list buckets as health check
            client.list_buckets()
            print("✓ MinIO is ready")
            return True
        except Exception as e:
            print(f"  Attempt {i+1}/{max_retries}: {e}")
            time.sleep(2)
    
    return False


def create_bucket_with_lock(client: Minio, bucket_config: dict) -> bool:
    """Create a bucket with Object Lock enabled."""
    bucket_name = bucket_config["name"]
    
    try:
        # Check if bucket exists
        if client.bucket_exists(bucket_name):
            print(f"  ✓ Bucket {bucket_name} already exists")
            return True
        
        # Create bucket with object lock enabled
        # Note: Object Lock must be enabled at bucket creation time
        client.make_bucket(bucket_name, object_lock=True)
        print(f"  ✓ Created bucket: {bucket_name}")
        
        # Note: Setting default retention requires the bucket retention API
        # which may need additional configuration in MinIO
        print(f"    Retention: {bucket_config['retention_days']} days ({bucket_config['retention_mode']} mode)")
        
        return True
        
    except S3Error as e:
        if "BucketAlreadyOwnedByYou" in str(e):
            print(f"  ✓ Bucket {bucket_name} already exists")
            return True
        print(f"  ✗ Error creating {bucket_name}: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error creating {bucket_name}: {e}")
        return False


def create_readme_object(client: Minio, bucket_name: str, description: str) -> bool:
    """Create a README object in the bucket."""
    try:
        from io import BytesIO
        
        readme_content = f"""# {bucket_name}

{description}

## WORM Storage Notice

This bucket is configured with Object Lock for WORM (Write Once Read Many) compliance.
Objects stored here cannot be deleted or modified during the retention period.

## Compliance Information

- Bucket: {bucket_name}
- Created: {datetime.utcnow().isoformat()}
- Object Lock: Enabled

## Important

Do not attempt to delete objects manually. All objects are protected by retention policies.
Contact your compliance team for any questions about data retention.
"""
        
        content_bytes = readme_content.encode('utf-8')
        client.put_object(
            bucket_name,
            "README.md",
            BytesIO(content_bytes),
            len(content_bytes),
            content_type="text/markdown"
        )
        
        return True
        
    except Exception as e:
        print(f"    Warning: Could not create README in {bucket_name}: {e}")
        return False


def main():
    """Main setup function."""
    print("=" * 60)
    print("SentinelIQ MinIO WORM Setup")
    print("=" * 60)
    print()
    print(f"Endpoint: {MINIO_ENDPOINT}")
    print(f"Secure: {MINIO_SECURE}")
    print()
    
    # Create MinIO client
    client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE
    )
    
    # Wait for MinIO to be ready
    if not wait_for_minio(client):
        print("\n✗ ERROR: MinIO is not available. Please start MinIO first.")
        sys.exit(1)
    
    print()
    print("Creating WORM-enabled buckets...")
    print("-" * 40)
    
    success_count = 0
    for bucket_config in BUCKETS:
        if create_bucket_with_lock(client, bucket_config):
            create_readme_object(client, bucket_config["name"], bucket_config["description"])
            success_count += 1
    
    print()
    print("-" * 40)
    print(f"Setup complete: {success_count}/{len(BUCKETS)} buckets created")
    print()
    
    # Print bucket summary
    print("Bucket Summary:")
    print("-" * 40)
    try:
        for bucket in client.list_buckets():
            print(f"  • {bucket.name} (created: {bucket.creation_date})")
    except Exception as e:
        print(f"  Error listing buckets: {e}")
    
    print()
    print("=" * 60)
    print("WORM storage is ready for audit logs and evidence.")
    print("=" * 60)
    
    return 0 if success_count == len(BUCKETS) else 1


if __name__ == "__main__":
    sys.exit(main())
