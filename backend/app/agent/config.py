"""Agent run settings and hard ceilings."""
from app.core.config import settings

CEILINGS = {
    "max_steps": 12,
    "max_tool_calls": 30,
    "wall_seconds": 300,
    "result_chars": 20_000,
    "max_concurrent_runs": 4,
}


def public_config() -> dict:
    return {
        "enabled": bool(settings.AGENT_ENABLED),
        "tool_mode": settings.AGENT_TOOL_MODE,
        "model": settings.AGENT_LLM_MODEL,
        "limits": {
            "max_steps": settings.AGENT_MAX_STEPS,
            "max_tool_calls": settings.AGENT_MAX_TOOL_CALLS,
            "wall_seconds": settings.AGENT_WALL_SECONDS,
            "result_chars": settings.AGENT_RESULT_CHARS,
            "max_concurrent_runs": settings.AGENT_MAX_CONCURRENT_RUNS,
        },
        "execution_mode": settings.AGENT_EXECUTION_MODE,
    }
