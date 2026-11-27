"""
WebSocket router for live SOC event feeds.
Implements /ws/live-events.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
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
    # The browser WebSocket API cannot attach Authorization headers. Require
    # the credential in the first frame instead of putting it in the URL,
    # where reverse proxies and access logs commonly record it.
    await websocket.accept()
    try:
        raw_auth = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        auth_message = json.loads(raw_auth)
        token = auth_message.get("token", "") if isinstance(auth_message, dict) and auth_message.get("type") == "AUTH" else ""
        with SessionLocal() as db:
            account = account_for_token(token, db) if token else None
    except (asyncio.TimeoutError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        account = None
    if account is None:
        await websocket.close(code=4401, reason="Valid analyst token required")
        return
    ws_manager.register(websocket)
    await websocket.send_json({"type": "AUTHENTICATED"})
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

