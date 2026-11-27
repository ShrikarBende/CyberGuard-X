# CyberGuard X light redesign

## Presentation changes

- Replaced the dark canvas tokens with the requested light cobalt palette, Hanken Grotesk, ambient canvas, reduced-transparency fallback, and light scrollbar styling in `frontend/src/index.css` and `frontend/tailwind.config.js`.
- Added `frontend/src/components/ui/Glass.jsx`; restyled the reusable controls and surfaces in `frontend/src/components/ui/` to use opaque data cards and reserve glass effects for floating chrome, popovers, tooltips, and dialogs.
- Updated the shell and navigation styling in `frontend/src/App.jsx`, `frontend/src/components/Sidebar.jsx`, `frontend/src/components/Header.jsx`, and `frontend/src/components/CommandPalette.jsx`. The existing navigation, keyboard shortcuts, role checks, notices, notification behavior, and shell state remain wired through their existing handlers.
- Updated chart colors and tooltips in `frontend/src/charts/chartTheme.js` and `frontend/src/charts/ChartTooltip.jsx`, and restyled visual components in `frontend/src/components/RiskFusion.jsx`, `frontend/src/components/MitreMatrix.jsx`, and `frontend/src/components/viz/`.
- Applied light-theme page styling in `frontend/src/pages/` for Overview, Live Feed, Incidents, Threat Intelligence, Explainability, AI Assistant, Data & Models, Evaluation, Agent Runs, and Approvals. Existing page data, forms, controls, and state branches were retained.
- Updated sign-in presentation in `frontend/src/components/LoginScreen.jsx` without changing login submission behavior.
- Added the self-hosted Hanken Grotesk font dependency and removed the unused Manrope font dependency from `frontend/package.json` and `frontend/package-lock.json`.

## Preserved behavior and workspace state

- No API service definitions, request/response shapes, authentication/session flow, hash routing, role gating, WebSocket handlers, polling intervals, or keyboard shortcut logic were intentionally changed.
- `frontend/src/services/api.js` contains pre-existing uncommitted agent/approval API edits and was not edited as part of this visual pass.
- Existing user changes in frontend files, including the agent/approval and incident work, were retained. Unrelated backend edits and the untracked `FRONTEND_UI_DOCUMENTATION.md` were left untouched.
- No commits were created because the worktree already contained unrelated changes and several edited frontend files also held pre-existing user edits; committing whole files would have included those unrelated changes.
- No recommendation or product behavior changes are included in this changelog.

## Verification

- `npm run build` — passed after correcting mismatched heading markup in `frontend/src/pages/DataManagement.jsx`.
- `npm run lint` — unavailable; `frontend/package.json` has no lint script.
- Browser screenshots and responsive viewport checks — not completed. Local browser access was unavailable from this chat, and the existing Chrome window indicated user input in progress. No screenshots are represented as captured.
- Backend-backed login, authenticated routes, live data, role-specific states, and form submissions were not verified in a browser session.
