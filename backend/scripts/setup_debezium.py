#!/usr/bin/env python3
"""
Debezium Connector Setup Script

Registers the Debezium CDC connector for the transactional outbox pattern.
Run after Debezium Connect is healthy.

Usage:
    python scripts/setup_debezium.py

This creates a connector that:
1. Monitors the event_outbox table in PostgreSQL
2. Routes events to Kafka topics based on event_type
3. Enables exactly-once event delivery via CDC
"""

import os
import sys
import time
import json
import requests

# Configuration
DEBEZIUM_URL = os.getenv("DEBEZIUM_URL", "http://localhost:8083")
CONNECTOR_CONFIG_PATH = os.getenv(
    "CONNECTOR_CONFIG", 
    os.path.join(os.path.dirname(__file__), "..", "config", "debezium-connector.json")
)

# Database configuration (from environment)
DB_HOST = os.getenv("POSTGRES_HOST", "postgres")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
DB_NAME = os.getenv("POSTGRES_DB", "sentineliq")


def wait_for_debezium(max_retries: int = 30) -> bool:
    """Wait for Debezium Connect to be ready."""
    print(f"Waiting for Debezium Connect at {DEBEZIUM_URL}...")
    
    for i in range(max_retries):
        try:
            response = requests.get(f"{DEBEZIUM_URL}/connectors", timeout=5)
            if response.status_code == 200:
                print("✓ Debezium Connect is ready")
                return True
        except requests.exceptions.RequestException as e:
            print(f"  Attempt {i+1}/{max_retries}: {e}")
        time.sleep(2)
    
    return False


def load_connector_config() -> dict:
    """Load connector configuration from JSON file."""
    with open(CONNECTOR_CONFIG_PATH, 'r') as f:
        config = json.load(f)
    
    # Override with environment variables if set
    config["config"]["database.hostname"] = DB_HOST
    config["config"]["database.port"] = DB_PORT
    config["config"]["database.user"] = DB_USER
    config["config"]["database.password"] = DB_PASSWORD
    config["config"]["database.dbname"] = DB_NAME
    
    return config


def get_existing_connectors() -> list:
    """Get list of existing connectors."""
    try:
        response = requests.get(f"{DEBEZIUM_URL}/connectors")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error getting connectors: {e}")
        return []


def delete_connector(name: str) -> bool:
    """Delete an existing connector."""
    try:
        response = requests.delete(f"{DEBEZIUM_URL}/connectors/{name}")
        if response.status_code in [200, 204]:
            print(f"  ✓ Deleted existing connector: {name}")
            return True
        elif response.status_code == 404:
            return True  # Already doesn't exist
        else:
            print(f"  ✗ Error deleting connector: {response.text}")
            return False
    except Exception as e:
        print(f"  ✗ Error deleting connector: {e}")
        return False


def create_connector(config: dict) -> bool:
    """Create a new connector."""
    connector_name = config["name"]
    
    try:
        response = requests.post(
            f"{DEBEZIUM_URL}/connectors",
            json=config,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code in [200, 201]:
            print(f"  ✓ Created connector: {connector_name}")
            return True
        elif response.status_code == 409:
            print(f"  ✓ Connector already exists: {connector_name}")
            return True
        else:
            print(f"  ✗ Error creating connector: {response.status_code}")
            print(f"    Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"  ✗ Error creating connector: {e}")
        return False


def get_connector_status(name: str) -> dict:
    """Get connector status."""
    try:
        response = requests.get(f"{DEBEZIUM_URL}/connectors/{name}/status")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def main():
    """Main setup function."""
    print("=" * 60)
    print("SentinelIQ Debezium CDC Setup")
    print("=" * 60)
    print()
    print(f"Debezium URL: {DEBEZIUM_URL}")
    print(f"Database: {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    print()
    
    # Wait for Debezium to be ready
    if not wait_for_debezium():
        print("\n✗ ERROR: Debezium Connect is not available.")
        print("  Please ensure Debezium is running: docker-compose up -d debezium")
        sys.exit(1)
    
    print()
    
    # Load connector configuration
    print("Loading connector configuration...")
    try:
        config = load_connector_config()
        print(f"  ✓ Loaded config for: {config['name']}")
    except FileNotFoundError:
        print(f"  ✗ Config file not found: {CONNECTOR_CONFIG_PATH}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"  ✗ Invalid JSON in config file: {e}")
        sys.exit(1)
    
    print()
    
    # Check for existing connectors
    print("Checking existing connectors...")
    existing = get_existing_connectors()
    print(f"  Found {len(existing)} existing connector(s): {existing}")
    
    connector_name = config["name"]
    if connector_name in existing:
        print(f"\n  Connector '{connector_name}' already exists.")
        print("  Deleting and recreating...")
        delete_connector(connector_name)
        time.sleep(2)
    
    print()
    
    # Create connector
    print("Creating Debezium connector...")
    if not create_connector(config):
        print("\n✗ Failed to create connector")
        sys.exit(1)
    
    # Wait for connector to start
    print("\nWaiting for connector to start...")
    time.sleep(5)
    
    # Check status
    status = get_connector_status(connector_name)
    print()
    print("Connector Status:")
    print("-" * 40)
    print(json.dumps(status, indent=2))
    
    print()
    print("=" * 60)
    print("Debezium CDC setup complete!")
    print()
    print("The connector will:")
    print("  1. Monitor the 'event_outbox' table in PostgreSQL")
    print("  2. Publish events to Kafka topics based on event_type")
    print("  3. Enable exactly-once event delivery via CDC")
    print()
    print("Kafka topic pattern: sentineliq.events.<event_type>")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
