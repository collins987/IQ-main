from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.security import decode_access_token
from app.models import User
from app.core.db import SessionLocal
import asyncio

router = APIRouter()

@router.websocket("/ws/events")
async def dashboard_events_ws(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return
    try:
        payload = decode_access_token(token)
        if not payload:
            await websocket.close(code=1008)
            return
        is_virtual = payload.get("is_virtual", False)
        if not is_virtual:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.id == payload.get("sub")).first()
                if not user or not user.is_active or user.role != "admin":
                    await websocket.close(code=1008)
                    return
            finally:
                db.close()
    except Exception:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({"type": "heartbeat"})
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        pass
