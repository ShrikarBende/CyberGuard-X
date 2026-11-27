from __future__ import annotations

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.database.session import Base
from app.rag import assistant


class _Retriever:
    def search(self, _query, _top_k):
        return [{
            "chunk_id": "guide-1", "title": "Incident response guidance",
            "section_title": "Preserve evidence", "text": "Preserve relevant logs for review.",
            "score": 0.9, "relevance_score": 0.9,
        }]


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def configured_provider(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_URL", "https://provider.invalid/chat")
    monkeypatch.setattr(settings, "LLM_API_KEY", "test-key")
    monkeypatch.setattr(settings, "RAG_MIN_RETRIEVAL_SCORE", 0.25)
    monkeypatch.setattr(assistant, "get_retriever", lambda: _Retriever())


def _run(db_session):
    return assistant.query_rag_assistant("How should I investigate this?", None, db_session)


def test_provider_success_returns_llm_answer(configured_provider, monkeypatch, db_session):
    monkeypatch.setattr(assistant.httpx, "post", lambda *args, **kwargs: _Response({
        "choices": [{"message": {"content": "Review the logs. [guide-1]"}}],
    }))
    answer = _run(db_session)
    assert answer["mode"] == "llm"
    assert answer["fallback"] is False
    assert "Review the logs." in answer["answer"]


@pytest.mark.parametrize("failure", [
    httpx.TimeoutException("provider timeout"),
    httpx.ConnectError("provider unavailable"),
    ValueError("invalid JSON payload"),
    ValueError("missing answer content"),
    AttributeError("malformed response shape"),
])
def test_provider_failures_return_extract_fallback(configured_provider, monkeypatch, db_session, failure):
    def fail(*_args, **_kwargs):
        if isinstance(failure, httpx.HTTPError):
            raise failure
        if str(failure) == "missing answer content":
            return _Response({"choices": []})
        return _Response(failure)

    monkeypatch.setattr(assistant.httpx, "post", fail)
    answer = _run(db_session)
    assert answer["mode"] == "extractive_fallback"
    assert answer["fallback"] is True
    assert answer["fallback_reason"]
    assert "Preserve relevant logs" in answer["answer"]


def test_provider_http_error_returns_extract_fallback(configured_provider, monkeypatch, db_session):
    request = httpx.Request("POST", "https://provider.invalid/chat")
    response = httpx.Response(503, request=request)

    def http_error(*_args, **_kwargs):
        response.raise_for_status()

    monkeypatch.setattr(assistant.httpx, "post", http_error)
    answer = _run(db_session)
    assert answer["mode"] == "extractive_fallback"
    assert answer["fallback"] is True
