from pathlib import Path
import sys
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT.parent / "scripts"))
import eval_agent
from app.agent.manifest import load_manifest
from app.database.session import Base


def test_offline_regression_suite_covers_f1_through_f5():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, autoflush=False)() as db:
        result = eval_agent._run_regression_suite(db, load_manifest("investigator"))
    engine.dispose()
    assert result["all_passed"] is True, result
    assert result["f4_injected_staged_proposals_discarded"] is True
    assert result["f5_tool_happy_run_finalized_report"] is True


def test_aggregate_reports_limit_reached_rate_and_document_labels_fake_llm():
    metrics = eval_agent._aggregate([
        {"label": "PortScan", "techniques": [], "valid_citations": 0, "citation_count": 0,
         "unsupported_techniques": 0, "technique_count": 0, "steps": 2, "tool_calls": 1,
         "latency_seconds": 0.1, "fallback": False, "limit_reached": True},
        {"label": "PortScan", "techniques": [], "valid_citations": 0, "citation_count": 0,
         "unsupported_techniques": 0, "technique_count": 0, "steps": 3, "tool_calls": 2,
         "latency_seconds": 0.2, "fallback": False, "limit_reached": False}], {"PortScan": []})
    assert metrics["limit_reached_rate"] == 0.5
    rendered = __import__("make_results_md").render_agent_section({
        "metrics": {"baseline": metrics, "agent": metrics}, "injection_suite": {"passed_count": 12, "payload_count": 12},
        "regression_suite": {"all_passed": True, "scope": "FakeLLM plumbing only"},
        "model_name": "FakeLLM-scripted-v1", "date_utc": "2026-11-25", "seed": 42,
        "sample_size": 2, "source_counts": {"held_out_cicids_replay": 1},
        "synthetic_demo_sample_count": 1, "used_fake_llm": True})
    assert "used FakeLLM: `true`" in rendered and "Limit reached rate" in rendered


def test_real_evaluation_requires_an_agent_url_without_needing_network(monkeypatch):
    monkeypatch.setattr(eval_agent.settings, "AGENT_LLM_API_URL", "")
    with pytest.raises(ValueError, match="AGENT_LLM_API_URL"):
        eval_agent.run(2, 42, "real")
