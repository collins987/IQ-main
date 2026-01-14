from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.security import decode_access_token
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
        if not payload or payload.get("role") != "admin":
            await websocket.close(code=1008)
            return
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
