"""Ceiling-clamped limits and simple enforcement helpers."""
from dataclasses import dataclass
from app.agent.config import CEILINGS
from app.core.config import settings


@dataclass(frozen=True)
class RunLimits:
    max_steps: int = settings.AGENT_MAX_STEPS
    max_tool_calls: int = settings.AGENT_MAX_TOOL_CALLS
    wall_seconds: int = settings.AGENT_WALL_SECONDS
    result_chars: int = settings.AGENT_RESULT_CHARS
    max_concurrent_runs: int = settings.AGENT_MAX_CONCURRENT_RUNS

    def as_dict(self) -> dict[str, int]:
        return {key: int(getattr(self, key)) for key in CEILINGS}


def clamp_to_ceilings(values: dict | None = None) -> RunLimits:
    values = values or {}
    defaults = RunLimits()
    clamped = {}
    for key, ceiling in CEILINGS.items():
        candidate = values.get(key, getattr(defaults, key))
        try:
            candidate = int(candidate)
        except (TypeError, ValueError):
            candidate = getattr(defaults, key)
        clamped[key] = min(max(candidate, 1), ceiling)
    return RunLimits(**clamped)


class RunLimitReached(RuntimeError):
    pass
