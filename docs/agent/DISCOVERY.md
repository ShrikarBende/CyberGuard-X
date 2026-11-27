# Agent Layer Discovery (P0)

Discovery was performed against the current workspace on 2026-11-25. The checkout was already
modified before this phase began; those changes were preserved. The baseline command was
`python -m pytest` from `backend/`: **128 passed, 6 skipped, 3 warnings in 138.08s**. The
working tree also contains uncommitted changes and untracked files, including existing edits to
`backend/app/api/endpoints.py`, `backend/app/correlation/engine.py`, `backend/app/rag/assistant.py`,
`backend/app/rag/indexer.py`, and frontend files. Therefore this is a baseline of the current
workspace, not a clean checkout. Six API end-to-end tests are marked Linux-only and were skipped
on Windows.

## Repository findings

### Models and persistence

`backend/app/models/entities.py` defines these relevant columns:

- `SecurityEvent`: `event_id`, `timestamp`, `user_id`, `device_id`, `source_ip`,
  `destination_ip`, `source_port`, `destination_port`, `event_category`, `event_type`, `status`,
  `privilege_level`, `process_name`, `command_line`, `bytes_transferred`, `location`,
  `raw_payload`, `dataset`, `scenario`, `dedup_hash`, `created_at`.
- `DetectionResult`: `detection_id`, `event_id`, `verdict`, `predicted_class`, `confidence`,
  `probability`, `anomaly_score`, `score`, `attack_probability`, `open_set_distance`,
  `reconstruction_error`, `model_version`, `tau`, `layer`, `details`, `created_at`.
- `Incident`: `incident_id`, `title`, `description`, `severity`, `status`,
  `threat_classification`, `overall_risk_score`, `user_id`, `device_id`, `attack_sequence`,
  `evidence`, `flow_count`, `group_key`, `first_detected_at`, `last_updated_at`.
- `InvestigationNote`: `note_id`, `incident_id`, `author`, `content`, `is_ai_generated`,
  `citations`, `created_at`.
- `AnalystActivity`: `activity_id`, `timestamp`, `analyst_name`, `action_type`, `target_entity`,
  `target_id`, `details`.
- `AnalystAccount`: `account_id`, `username`, `password_hash`, `role`, `is_active`, `created_at`,
  `updated_at`.

### Authentication and audit

`app/auth.py` provides `get_current_analyst(credentials=Depends(bearer_scheme),
db=Depends(get_db), request=None)`, resolving the bearer token to the active `AnalystAccount`.
The username is `account.username` (the token subject is also the username). The HTTP middleware
validates it and stores the account in `request.state.analyst`. `require_roles(*roles)` returns a
dependency that raises 403 when `account.role` is not permitted; roles are `viewer`, `analyst`,
and `admin`.

`app/audit.py` signature is
`record_analyst_activity(db: Session, analyst_name: str, action_type: str,
target_entity: str | None = None, target_id: str | None = None,
details: dict[str, Any] | None = None) -> AnalystActivity`. It adds the row to the session; the
caller controls commit.

### Configuration, database, and migrations

`app/core/config.py` uses Pydantic Settings, reads the project-root `.env`, and ignores unknown
settings. The existing LLM settings are `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_API_URL`, and
`LLM_MODEL`. The model bundle default resolves to
`backend/saved_models/cicids2017_medium_lightgbm.bundle.pkl`. `backend/.env.example` does not
exist; a project-root `.env.example` exists. **PyYAML is not listed in `backend/requirements.txt`.**

`app/database/session.py` creates SQLAlchemy `Base`, `engine`, and `SessionLocal`; `get_db()` yields
and closes a request session. SQLite paths are resolved relative to `backend/`, and SQLite uses
`check_same_thread=False` and foreign-key/WAL pragmas.

`alembic heads` reports one head: **`3e3f12404ef0`**, following baseline
`73715c0b6c8b`. `alembic/env.py` imports `app.models.entities` and sets `target_metadata = Base.metadata`.
The main app's legacy schema match excludes only `analyst_accounts` today. Importing agent models
into `Base.metadata` will require the prompt's minimal `agent_` exclusion or equivalent safe handling.

### WebSockets and correlation

`WebSocketManager.broadcast(self, message)` is **async**. A worker thread cannot safely call it as
a normal synchronous method. Use frontend polling unless the application loop is captured and a
thread-safe scheduling path is proven.

`app/correlation/engine.py` has pure `correlate_events(events, window_minutes=None)` for finding
candidate incidents from event rows; `run_correlation(db, ...)` is the persistence wrapper.

### Retrieval and existing investigation

`app/rag/indexer.py` exposes `get_retriever(force_rebuild=False)` and
`KnowledgeRetriever.search(query, top_k=None, extra_documents=None) -> list[dict]`. Search results
carry document/chunk metadata, relevance scores, and text. The current workspace has an existing
`backend/app/rag/agent.py` and retriever module, plus modifications to `assistant.py` and
`indexer.py`; this differs from the prompt's description of the repo as having no agent layer.
The requested layer should live under the separate `backend/app/agent/` path and must inspect
these modified files before relying on their interfaces. The inspected `assistant.py` contains
`_untrusted`, `_validate_investigation_citations`, `_stored_incident_evidence`,
`_resolved_incident_documents`, `_incident_investigation_evidence`, and
`investigate_incident`.

### Tests and CI

`backend/tests/conftest.py` does not globally replace `get_db`; it sets a temporary results-output
directory for pytest and marks platform/data-specific tests. `tests/test_endpoints_e2e.py` overrides
`get_db` with a temporary SQLite database, creates `Base.metadata`, and seeds admin, analyst, and
viewer accounts. Other tests supply their own fixtures or temporary engines. The startup bundle
check is in the FastAPI lifespan (`_print_startup_summary`); the default configured bundle exists
in `backend/saved_models/`. API tests that import the app do not run lifespan through their
ASGITransport fixture.

`.github/workflows/` contains a full-stack CI workflow: backend tests run on Ubuntu/Python 3.11
with SQLite, Alembic upgrade, and `python -m pytest backend/tests -v`; frontend CI runs
`npm ci` and `npm run build` on Node 20. `docker-compose.yml` runs the backend and frontend and
sets `LLM_PROVIDER=template_fallback`.

### Frontend integration surface

The frontend is React/Vite. `src/App.jsx` manages a page key itself and lazily imports pages with
`React.lazy`; it is not a React Router route tree. Page selection is synchronized to URL hash and
session storage. `src/components/Sidebar.jsx` defines navigation and hides the existing AI
Assistant from viewers. `src/services/api.js` centralizes authenticated `fetchJson` calls, reads
`cyberguardx_access_token` from `sessionStorage`, and dispatches shared session-expired/forbidden
events. App styling is Tailwind plus `src/index.css` and existing shared UI components. New pages
should follow this state-based navigation and API pattern.

## Explicit answers

1. `SecurityEvent` has `source_ip` and `destination_ip` columns; they are not confined to
   `raw_payload` (which is an additional JSON column).
2. Alembic's single head is `3e3f12404ef0`. `env.py` imports the entity module and uses
   `Base.metadata`.
3. `ws_manager.broadcast` is async. Worker-thread broadcasting is not established as safe;
   frontend polling is the conservative choice.
4. PyYAML is absent from `backend/requirements.txt`.
5. Tests do override `get_db` in the HTTP end-to-end fixture, not globally. The configured model
   bundle path is `backend/saved_models/cicids2017_medium_lightgbm.bundle.pkl`; tests import the
   app without entering its startup lifespan, while startup checks the configured path.
6. `record_analyst_activity(db, analyst_name, action_type, target_entity=None, target_id=None,
   details=None) -> AnalystActivity`; it adds, but does not commit, the audit row.

## Safe interpretation notes

- The checkout is seven commits behind `origin/master` and has extensive pre-existing working-tree
  changes. This phase did not modify or discard any of them. Later commits must stage only files
  introduced for this task.
- The prompt's Phase 0 baseline gate passes for the current workspace: 128 passed and 6 skipped.
- H9 names only the `agent_` prefix for new metadata exclusions, but its required table list also
  includes `action_proposals`, which does not have that prefix. The baseline match therefore also
  excludes this one table explicitly; without it, a valid legacy schema would fail to upgrade.
- The prompt's proposed `get_explanation` tool calls the existing explainability endpoint directly,
  while discovery confirms that endpoint can mutate `risk_detail.top_contributing_features` and
  commit. To honor H3 (only `propose_action` may write), the implemented tool uses the existing
  read-only `_incident_investigation_evidence` assembler and omits cached/computed SHAP output.
- PyYAML would need to be added only if YAML manifests are implemented as specified.
- The workspace contains related pre-existing RAG agent code; it is distinct from the requested
  opt-in investigation service and is not evidence that the requested API, persistence, or
  approval flow exists.
