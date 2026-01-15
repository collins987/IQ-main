
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.security import decode_access_token
from app.models import User
from app.core.db import SessionLocal
import asyncio
import logging

logger = logging.getLogger("sentineliq.dashboard")
router = APIRouter()

@router.websocket("/ws/events")
async def dashboard_events_ws(websocket: WebSocket):
    token = websocket.query_params.get("token")
    logger.info(f"WebSocket endpoint /api/admin/dashboard/ws/events: Connection attempt received")
    if not token:
        logger.warning("WebSocket connection rejected: No token provided")
        await websocket.close(code=1008)
        return
    try:
        payload = decode_access_token(token)  # Direct function call, not decorator
        if not payload:
            logger.warning("WebSocket connection rejected: No payload decoded from token")
            await websocket.close(code=1008)
            return
        is_virtual = payload.get("is_virtual", False)
        if not is_virtual:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.id == payload.get("sub")).first()
                if not user or not user.is_active or user.role != "admin":
                    logger.warning(f"WebSocket connection rejected: DB admin not found or inactive (user={user})")
                    await websocket.close(code=1008)
                    return
            finally:
                db.close()
        # If is_virtual is True, allow connection
    except Exception as e:
        logger.warning(f"WebSocket connection rejected: Invalid token ({e})")
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({"type": "heartbeat"})
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        logger.info("WebSocket admin disconnected")
