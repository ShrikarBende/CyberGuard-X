# Agent layer fix-pass notes

## F1 — report confirmation language

- Reproduced in `test_unconfirmed_summary_is_preserved_byte_for_byte` and `test_assertive_confirmation_language_is_flagged_without_rewriting` on the pre-fix code.
- The old blanket replacement changed `unconfirmed` to `ununconfirmed` and changed affirmative prose instead of surfacing it.
- Fixed by preserving report strings and counting confirmation-language phrases across the summary, findings, and hypotheses. The validator adds the review limitation; the `assessment` schema still rejects `confirmed`.
- Verification: `python -m pytest tests/agent/test_report_hardening.py tests/agent/test_core.py -q` — 9 passed, 1 skipped.
