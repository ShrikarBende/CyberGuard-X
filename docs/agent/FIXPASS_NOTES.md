# Agent layer fix-pass notes

## F1 — report confirmation language

- Reproduced in `test_unconfirmed_summary_is_preserved_byte_for_byte` and `test_assertive_confirmation_language_is_flagged_without_rewriting` on the pre-fix code.
- The old blanket replacement changed `unconfirmed` to `ununconfirmed` and changed affirmative prose instead of surfacing it.
- Fixed by preserving report strings and counting confirmation-language phrases across the summary, findings, and hypotheses. The validator adds the review limitation; the `assessment` schema still rejects `confirmed`.
- Verification: `python -m pytest tests/agent/test_report_hardening.py tests/agent/test_core.py -q` — 9 passed, 1 skipped.

## F2 — preserve injection validation counts

- Reproduced in `test_tool_data_injection_flag_survives_report_validation`: an injection in the baseline tool result was detected by the loop but the saved validation count was zero.
- Fixed by adding report-text flags to the incoming tool-data flag count instead of replacing it.
- Verification: `python -m pytest tests/agent/test_report_hardening.py tests/agent/test_loop.py -q` — 9 passed.

## F3 — scan only attacker-controlled telemetry text

- Reproduced false positives: the old detector flagged serialized `FALSE_POSITIVE` status and ordinary playbook prose about reducing false positives. A real raw-payload instruction remained detectable.
- Added `ToolResult.scan_text` and `attacker_text(event)`; event-returning tools supply only selected telemetry strings and raw-payload string values. Curated knowledge and correlated-status data leave `scan_text` empty. The loop now scans only this field.
- Replaced the bare false-positive phrase matcher with an imperative instruction matcher; retained Unicode normalization, homoglyph folding, and zero-width stripping.
- Updated existing `test_injection_text_cannot_change_assessment_or_echo_system_prompt` fake tools to populate `scan_text`, because injection detection now follows the explicit scan-text contract. Its security expectation is unchanged.
- Verification: `python -m pytest tests/agent/test_report_hardening.py tests/agent/test_loop.py -q` — 13 passed.

## F4 — stage proposals until a successful run

- Reproduced that a proposal tool call persisted a pending row before the investigation completed.
- Proposal validation is now pure and persistence is separate. Tool calls stage their requested actions in the per-run registry; the service materializes a deduplicated set of at most five staged and report recommendations only after report validation succeeds.
- Injected runs discard staged/report actions and record `agent_proposals_discarded`; fallback and cancellation paths do not materialize any proposals.
- Verification: `python -m pytest backend/tests/agent/test_proposals.py backend/tests/agent/test_service.py -q` — 14 passed.

## F5 — finalize step/tool limits with retrieved evidence

- Reproduced that a tool call on the last allowed step immediately raised `RunLimitReached`, even when a no-tools report call could complete the run.
- The loop now refuses calls beyond the tool budget with an error result and makes a final no-tools report request after step/tool exhaustion. Invalid finalization and wall-clock expiry raise `RunLimitReached`; the worker records `limit_reached` with its deterministic baseline report and a `limit_reached:` fallback reason.
- Added offline tests for finalization after the last step, over-budget tool refusal, and persisted `limit_reached` status.
- Verification: `python -m pytest backend/tests/agent/test_loop.py backend/tests/agent/test_service.py backend/tests/agent/test_proposals.py -q` — 21 passed.
- Phase A verification: `LLM_API_URL='' LLM_API_KEY='' python -m pytest backend/tests -v` — 170 passed, 7 skipped; clearing the general RAG provider variables kept tests offline. The first run without those overrides reached the configured external RAG provider and failed two data-marked tests at DNS; no product code was changed for those environment-dependent failures.
- Existing agent test updated: `test_cancel_and_step_limits_are_checked_between_steps` now expects the intentional failed-finalization reason introduced by F5.

## F6 — constrain tool schemas and descriptions

- Reproduced missing enums for related-event fields, knowledge source types, proposal action/target types, and an unbounded proposal confidence. Invalid related-event fields passed validation and failed later in the handler.
- Added enum-constrained schemas, bounded confidence, distinct tool-specific descriptions, and safe validation-error responses.
- Verification: `python -m pytest backend/tests/agent/test_tool_quality.py -q` — 2 passed.

## F7 — return read-only explainability summaries

- Code inspection: `get_explainability` reads `RiskScore.top_contributing_features`, `RiskScore.risk_breakdown`, and `RiskScore.explanation_summary`. Detector producers store endpoint `top_contributing_features`, `feature_residuals`, and `reconstruction_error`; user `temporal_attention` and `variable_selection_weights`; graph `top_suspicious_edges` and graph score; network `risk_breakdown`, `risk_fusion`, `s_network_flow`, `open_set_score`, `centroid_distance`, and `open_set_label`. Network detection rows also contain `cicids_features` and `class_probabilities`; those raw vectors are excluded from agent output.
- Reproduced duplicate behavior: before the change, `get_explanation` returned the same incident evidence assembler payload as `get_incident_evidence`.
- Implemented direct read-only extraction with whitelisted detection fields and at most ten entries for list fields. Missing explanations return `available: false` with the incident evidence ID. Detection detail uses the same whitelist and does not expose raw feature vectors.
- Verification: `python -m pytest backend/tests/agent/test_tool_quality.py -q` — 3 passed; test confirms output differs, remains read-only, and omits feature vectors.

## F8 — anchor related-event searches to incident time

- Reproduced that a replayed incident from 2024 returned no matching rows because the query window was based on the current time.
- Related-event queries now span `first_detected_at - window` through `last_updated_at + window`. Naive SQLite datetimes are treated as UTC; aware datetimes are converted to UTC before comparison.
- Verification: `python -m pytest backend/tests/agent/test_tool_quality.py -q` — 4 passed. The same normalization path is used for SQLite and PostgreSQL; no PostgreSQL service is configured here for a live integration run.
