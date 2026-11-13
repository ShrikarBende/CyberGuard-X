"""
WebSocket router for live SOC event feeds.
Implements /ws/live-events.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.websocket_manager import ws_manager
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSocket Stream"])


@router.websocket("/ws/live-events")
@router.websocket("/ws/stream")
@router.websocket("/ws/alerts")
async def websocket_live_events_endpoint(websocket: WebSocket):
    """Real-time streaming endpoint for security events and alert notifications."""
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

