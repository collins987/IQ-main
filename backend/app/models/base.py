"""
SQLAlchemy Base and common utilities for all models.

This module exists to prevent circular imports.
All model modules should import Base from here.
"""

from sqlalchemy.orm import declarative_base
import uuid

Base = declarative_base()


def generate_uuid():
    """Generate a UUID string for primary keys."""
    return str(uuid.uuid4())
