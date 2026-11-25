"""Strict YAML agent-manifest loading."""
from pathlib import Path
from typing import Literal
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from app.agent.limits import clamp_to_ceilings

MANIFEST_DIR = Path(__file__).resolve().parent / "manifests"
KNOWN_TOOLS = {
    "run_baseline_investigation", "get_incident_evidence", "get_explanation",
    "get_detection_detail", "search_knowledge", "find_related_events",
    "get_correlated_incidents", "list_unknown_candidates", "propose_action",
}


class AgentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    description: str = Field(min_length=1, max_length=500)
    needs: list[str] = Field(min_length=1)
    limits: dict[str, int] = Field(default_factory=dict)
    system: str = Field(min_length=1, max_length=12000)
    conclusion: Literal["json"]


def load_manifest(name: str) -> AgentManifest:
    if name not in {"investigator", "unknown_hunter"}:
        raise ValueError("Unknown agent manifest")
    path = MANIFEST_DIR / f"{name}.yaml"
    with path.open("r", encoding="utf-8") as source:
        value = yaml.safe_load(source)
    manifest = AgentManifest.model_validate(value)
    unknown = set(manifest.needs) - KNOWN_TOOLS
    if unknown or len(manifest.needs) != len(set(manifest.needs)):
        raise ValueError("Manifest contains unknown or duplicate tools")
    if set(manifest.limits) - {"max_steps", "max_tool_calls", "wall_seconds", "result_chars", "max_concurrent_runs"}:
        raise ValueError("Manifest contains unknown limits")
    for key, value in manifest.limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"Manifest limit {key} must be a positive integer")
    # Validate types here and clamp values at call time.
    clamp_to_ceilings(manifest.limits)
    return manifest
