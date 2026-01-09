from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
import os
import logging

logger = logging.getLogger("sentineliq.db")

# Database URL with sensible default for local development
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://sentineliq:sentineliq@postgres:5432/sentineliq"
)

# Validate DATABASE_URL is set in production
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Set it to your PostgreSQL connection string."
    )

# Create engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",
    pool_pre_ping=True,  # Verify connections before use
    pool_size=5,
    max_overflow=10,
    pool_recycle=300,  # Recycle connections every 5 minutes
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database tables."""
    from app.models import Base
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def get_db():
    """
    Dependency for FastAPI routes.
    Yields a database session and ensures cleanup.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session():
    """
    Context manager for database sessions.
    Use for non-FastAPI code (services, background tasks).
    
    Usage:
        with db_session() as db:
            db.query(User).all()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_db_connection() -> bool:
    """Check if database is reachable."""
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False
