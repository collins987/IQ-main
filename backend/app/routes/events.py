"""
Event Ingestion Gateway - FastAPI router for ingesting events into SentinelIQ.
Implements the transactional outbox pattern for guaranteed event delivery.
"""

import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.schemas.event import SentinelEvent
from app.models import User
from app.dependencies import get_current_user, get_db
from app.models.events import EventOutbox
from app.services.redis_stream import get_redis_stream_manager
import json

logger = logging.getLogger("sentineliq.gateway")

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("/ingest")
async def ingest_event(
    event: SentinelEvent,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = None
) -> dict:
    """
    Ingest an event into SentinelIQ.
    
    Implements transactional outbox pattern:
    1. Write event to postgres outbox table (in transaction)
    2. Return 200 to caller (guaranteed)
    3. Worker reads from outbox and publishes to Redis Streams
    4. Prevents message loss if server crashes between write and publish
    
    Events include:
    - Authentication (login, logout, failed)
    - Transactions (attempted, completed, failed)
    - Data access (read, write, delete)
    - RBAC violations
    """
    
    try:
        # Enrich event with request context
        event.actor.ip_address = request.client.host if request.client else event.actor.ip_address
        event.actor.user_agent = request.headers.get("user-agent", "unknown")
        event.timestamp = datetime.utcnow()
        
        # Validate event
        if not event.event_id:
            logger.error("Event missing event_id")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="event_id is required"
            )
        
        if not event.event_type:
            logger.error("Event missing event_type")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="event_type is required"
            )
        
        # Write to transactional outbox
        outbox_entry = EventOutbox(
            id=event.event_id,
            event_type=event.event_type,
            user_id=event.actor.user_id,
            event_data=event.dict(),
            created_at=datetime.utcnow(),
            is_processed=False
        )
        
        db.add(outbox_entry)
        db.commit()
        
        logger.info(f"Event ingested: {event.event_id} ({event.event_type}) - User: {event.actor.user_id}")
        
        return {
            "status": "accepted",
            "event_id": event.event_id,
            "message": "Event queued for processing"
        }
        
    except Exception as e:
        logger.error(f"Error ingesting event: {e}")
        db.rollback()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest event"
        )


@router.post("/auth-events")
async def ingest_auth_event(
    event_data: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = None
) -> dict:
    """Convenience endpoint for authentication events."""
    
    from app.schemas.event import AuthenticationPayload, ActorContext, GeoContext
    
    try:
        # Build event from auth data
        event = SentinelEvent(
            event_type=event_data.get("event_type"),
            actor=ActorContext(
                user_id=event_data.get("user_id"),
                ip_address=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent", "unknown"),
                device_fingerprint=event_data.get("device_fingerprint", "unknown")
            ),
            context=GeoContext(
                geo_lat=event_data.get("geo_lat", 0.0),
                geo_lon=event_data.get("geo_lon", 0.0),
                country_code=event_data.get("country_code")
            ),
            payload=event_data.get("payload", {})
        )
        
        # Use main ingestion
        return await ingest_event(event, request, db, current_user)
        
    except Exception as e:
        logger.error(f"Error ingesting auth event: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid auth event: {str(e)}"
        )


@router.post("/transaction-events")
async def ingest_transaction_event(
    event_data: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = None
) -> dict:
    """Convenience endpoint for transaction events."""
    
    from app.schemas.event import TransactionPayload, ActorContext, GeoContext
    
    try:
        event = SentinelEvent(
            event_type=event_data.get("event_type"),
            actor=ActorContext(
                user_id=event_data.get("user_id"),
                ip_address=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent", "unknown"),
                device_fingerprint=event_data.get("device_fingerprint", "unknown")
            ),
            context=GeoContext(
                geo_lat=event_data.get("geo_lat", 0.0),
                geo_lon=event_data.get("geo_lon", 0.0),
                country_code=event_data.get("country_code")
            ),
            payload=event_data.get("payload", {})
        )
        
        return await ingest_event(event, request, db, current_user)
        
    except Exception as e:
        logger.error(f"Error ingesting transaction event: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid transaction event: {str(e)}"
        )


@router.get("/health")
async def gateway_health() -> dict:
    """Health check endpoint."""
    redis = get_redis_stream_manager()
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "redis_connected": redis.health_check()
    }
