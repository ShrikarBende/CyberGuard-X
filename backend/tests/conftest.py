import sys
from pathlib import Path
import asyncio

# Starlette's TestClient can block while creating its asyncio self-pipe under
# Windows' default Proactor loop. Use the selector loop for test clients.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
