from __future__ import annotations

from fastapi.responses import JSONResponse

from app import main


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _query):
        return 1


class _Engine:
    def __init__(self, error=None):
        self.error = error

    def connect(self):
        if self.error:
            raise self.error
        return _Connection()


def test_health_reports_database_connected(monkeypatch):
    monkeypatch.setattr(main, "engine", _Engine())
    assert main.health() == {
        "status": "healthy", "service": "CyberGuard X Backend", "database": "connected",
    }


def test_health_reports_database_unavailable(monkeypatch):
    monkeypatch.setattr(main, "engine", _Engine(ConnectionError("private detail")))
    response = main.health()
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert b'"database":"disconnected"' in response.body
    assert b"private detail" not in response.body
