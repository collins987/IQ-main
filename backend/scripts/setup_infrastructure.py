#!/usr/bin/env python3
"""
SentinelIQ Infrastructure Setup

Master script to initialize all SentinelIQ infrastructure:
1. MinIO WORM storage buckets
2. Vault secrets engine
3. Debezium CDC connector
4. Kafka topics

Usage:
    python scripts/setup_infrastructure.py [--component COMPONENT]

Components:
    all     - Set up everything (default)
    minio   - Set up MinIO WORM buckets only
    vault   - Set up Vault secrets only
    debezium - Set up Debezium CDC only
    kafka   - Create Kafka topics only

Requirements:
    - Docker Compose stack running
    - All services healthy
"""

import os
import sys
import argparse
import subprocess
import time
from typing import List, Tuple


def print_header(text: str):
    """Print a formatted header."""
    print()
    print("=" * 60)
    print(text)
    print("=" * 60)
    print()


def print_step(step: int, total: int, text: str):
    """Print a step indicator."""
    print(f"\n[{step}/{total}] {text}")
    print("-" * 40)


def run_script(script_path: str) -> Tuple[bool, str]:
    """Run a Python script and return success status and output."""
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Script timed out"
    except Exception as e:
        return False, str(e)


def check_docker_service(service_name: str) -> bool:
    """Check if a Docker service is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={service_name}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )
        return service_name in result.stdout
    except Exception:
        return False


def setup_minio() -> bool:
    """Set up MinIO WORM storage."""
    script_path = os.path.join(os.path.dirname(__file__), "setup_minio_worm.py")
    
    if not os.path.exists(script_path):
        print("  ✗ MinIO setup script not found")
        return False
    
    success, output = run_script(script_path)
    print(output)
    return success


def setup_vault() -> bool:
    """Set up Vault secrets engine."""
    print("Setting up Vault secrets engine...")
    
    # Check if Vault is running
    if not check_docker_service("sentineliq_vault"):
        print("  ✗ Vault container not running")
        return False
    
    try:
        import hvac
        
        vault_addr = os.getenv("VAULT_ADDR", "http://localhost:8200")
        vault_token = os.getenv("VAULT_TOKEN", "devroot")
        
        client = hvac.Client(url=vault_addr, token=vault_token)
        
        if not client.is_authenticated():
            print("  ✗ Vault authentication failed")
            return False
        
        print("  ✓ Connected to Vault")
        
        # Enable KV secrets engine v2
        try:
            client.sys.enable_secrets_engine(
                backend_type="kv",
                path="secret",
                options={"version": "2"}
            )
            print("  ✓ Enabled KV secrets engine v2")
        except hvac.exceptions.InvalidRequest:
            print("  ✓ KV secrets engine already enabled")
        
        # Enable Transit engine for encryption
        try:
            client.sys.enable_secrets_engine(
                backend_type="transit",
                path="transit"
            )
            print("  ✓ Enabled Transit secrets engine")
        except hvac.exceptions.InvalidRequest:
            print("  ✓ Transit secrets engine already enabled")
        
        # Create encryption keys
        try:
            client.secrets.transit.create_key("sentineliq-pii")
            print("  ✓ Created encryption key: sentineliq-pii")
        except hvac.exceptions.InvalidRequest:
            print("  ✓ Encryption key 'sentineliq-pii' already exists")
        
        try:
            client.secrets.transit.create_key("sentineliq-audit")
            print("  ✓ Created encryption key: sentineliq-audit")
        except hvac.exceptions.InvalidRequest:
            print("  ✓ Encryption key 'sentineliq-audit' already exists")
        
        # Store initial secrets
        client.secrets.kv.v2.create_or_update_secret(
            path="sentineliq/config",
            secret={
                "database_url": os.getenv("DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/sentineliq"),
                "redis_url": os.getenv("REDIS_URL", "redis://redis:6379/0"),
                "jwt_secret": os.getenv("SECRET_KEY", "your-jwt-secret-here"),
                "setup_complete": "true",
                "setup_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        )
        print("  ✓ Stored initial configuration secrets")
        
        return True
        
    except ImportError:
        print("  ✗ hvac package not installed")
        return False
    except Exception as e:
        print(f"  ✗ Vault setup error: {e}")
        return False


def setup_debezium() -> bool:
    """Set up Debezium CDC connector."""
    script_path = os.path.join(os.path.dirname(__file__), "setup_debezium.py")
    
    if not os.path.exists(script_path):
        print("  ✗ Debezium setup script not found")
        return False
    
    success, output = run_script(script_path)
    print(output)
    return success


def setup_kafka_topics() -> bool:
    """Create Kafka topics."""
    print("Setting up Kafka topics...")
    
    if not check_docker_service("sentineliq_kafka"):
        print("  ✗ Kafka container not running")
        return False
    
    topics = [
        # Raw events
        ("raw.ingest.events", 3, 1),
        ("raw.ingest.logins", 3, 1),
        ("raw.ingest.transactions", 3, 1),
        
        # Core processing
        ("core.risk.scored", 3, 1),
        ("core.fraud.detected", 3, 1),
        
        # Operations
        ("ops.alerts.high", 3, 1),
        ("ops.alerts.medium", 3, 1),
        ("ops.notifications.email", 3, 1),
        
        # Audit
        ("audit.compliance.archive", 3, 1),
        ("audit.user.activity", 3, 1),
        
        # Debezium CDC
        ("sentineliq.events.transaction", 3, 1),
        ("sentineliq.events.login", 3, 1),
        ("sentineliq.events.alert", 3, 1),
    ]
    
    success_count = 0
    for topic_name, partitions, replication in topics:
        try:
            result = subprocess.run(
                [
                    "docker", "exec", "sentineliq_kafka",
                    "kafka-topics", "--create",
                    "--topic", topic_name,
                    "--partitions", str(partitions),
                    "--replication-factor", str(replication),
                    "--if-not-exists",
                    "--bootstrap-server", "localhost:29092"
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 or "already exists" in result.stderr.lower():
                print(f"  ✓ Topic: {topic_name}")
                success_count += 1
            else:
                print(f"  ✗ Topic: {topic_name} - {result.stderr}")
                
        except Exception as e:
            print(f"  ✗ Topic: {topic_name} - {e}")
    
    print(f"\n  Created {success_count}/{len(topics)} topics")
    return success_count == len(topics)


def main():
    """Main setup function."""
    parser = argparse.ArgumentParser(description="SentinelIQ Infrastructure Setup")
    parser.add_argument(
        "--component",
        choices=["all", "minio", "vault", "debezium", "kafka"],
        default="all",
        help="Component to set up (default: all)"
    )
    args = parser.parse_args()
    
    print_header("SentinelIQ Infrastructure Setup")
    
    # Determine which components to set up
    components = {
        "minio": ("MinIO WORM Storage", setup_minio),
        "vault": ("HashiCorp Vault", setup_vault),
        "kafka": ("Kafka Topics", setup_kafka_topics),
        "debezium": ("Debezium CDC", setup_debezium),
    }
    
    if args.component == "all":
        to_setup = list(components.keys())
    else:
        to_setup = [args.component]
    
    total = len(to_setup)
    results = {}
    
    for i, component in enumerate(to_setup, 1):
        name, setup_func = components[component]
        print_step(i, total, name)
        
        try:
            results[component] = setup_func()
        except Exception as e:
            print(f"  ✗ Error: {e}")
            results[component] = False
    
    # Print summary
    print_header("Setup Summary")
    
    for component, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        print(f"  {components[component][0]}: {status}")
    
    # Overall status
    all_success = all(results.values())
    print()
    if all_success:
        print("✓ All components set up successfully!")
        print()
        print("Next steps:")
        print("  1. Verify services: docker-compose ps")
        print("  2. Check API health: curl http://localhost:8000/health/detailed")
        print("  3. View Kafka UI: http://localhost:8086")
        print("  4. View Grafana: http://localhost:3001")
    else:
        print("✗ Some components failed to set up.")
        print("  Check the logs above for details.")
    
    return 0 if all_success else 1


if __name__ == "__main__":
    sys.exit(main())
