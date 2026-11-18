"""
WebSocket router for live SOC event feeds.
Implements /ws/live-events.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.websocket_manager import ws_manager
from app.auth import account_for_token
from app.database.session import SessionLocal
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSocket Stream"])


@router.websocket("/ws/live-events")
@router.websocket("/ws/stream")
@router.websocket("/ws/alerts")
async def websocket_live_events_endpoint(websocket: WebSocket):
    """Real-time streaming endpoint for security events and alert notifications."""
    token = websocket.query_params.get("token", "")
    try:
        with SessionLocal() as db:
            account = account_for_token(token, db) if token else None
    except (ValueError, TypeError, UnicodeError):
        account = None
    if account is None:
        await websocket.accept()
        await websocket.close(code=4401, reason="Valid analyst token required")
        return
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)

