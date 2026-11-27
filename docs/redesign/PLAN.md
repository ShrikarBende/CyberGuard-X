# CyberGuard X light redesign plan

## Scope and sequence

1. Inspect the current frontend files named in the master prompt and the working-tree diffs. Preserve the already-present agent/approval and incident UI work; do not alter API, authentication, routing, role checks, keyboard behavior, polling, or payload shapes.
2. Establish the current app baseline by installing frontend dependencies if needed and starting Vite once. Record whether the app starts and whether the existing backend is available.
3. Phase 1 — replace visual tokens/canvas/font rules in `frontend/src/index.css`, `frontend/tailwind.config.js`, and `frontend/package.json` (add local Hanken Grotesk only if dependency install is available); update lockfile only as required by that font dependency.
4. Phase 2 — add `frontend/src/components/ui/Glass.jsx`; restyle shared UI primitives while preserving filenames, exports, and prop signatures.
5. Phase 3 — restyle `frontend/src/App.jsx`, `components/Sidebar.jsx`, `components/Header.jsx`, `components/CommandPalette.jsx`, notices and the shortcut dialog; retain shell state and navigation behavior.
6. Phase 4 — update chart theme/tooltip and restyle page components in the specified order, including `RiskFusion`, `MitreMatrix`, `DistanceMap`, LoginScreen, all ten pages, and LiveMonitoring.css. Preserve all user-visible flows and data access.
7. Phase 5 — pass over loading/empty/error/accessibility states and responsive behavior; remove obsolete dark-only presentation classes without changing runtime behavior.
8. Build the app, run lint only if a script exists, and use the browser at required widths for visual verification/screenshots. Record behavior preserved, conflicts and verification in `docs/redesign/CHANGELOG.md`.

## Working tree constraints

At inspection time, the repository contains unrelated backend changes and existing frontend changes in `App.jsx`, `Sidebar.jsx`, `Skeleton.jsx`, `IncidentManagement.jsx`, `LiveMonitoring.css`, and `LiveMonitoring.jsx`, plus an untracked `FRONTEND_UI_DOCUMENTATION.md`. Keep all of those changes intact. Because the existing diffs overlap phases 2–4, avoid committing a whole dirty file unless a safe patch-only commit can be produced without including unrelated work.

## Baseline status

Frontend dependencies were already present, and Vite started in development mode. The production build initially found a mismatched `h1`/`h3` pair in `DataManagement.jsx`; that heading markup was corrected, and the subsequent build passed. The backend was not started or validated during the baseline check. The frontend package has no `lint` script.

Visual browser verification was attempted after the build. This chat could not open a local browser tab, and the existing Chrome window reported user input in progress, so no screenshots were captured and no browser interaction was attempted further.

## Completion notes

The token, shared primitive, shell, chart, and page styling pass is implemented. Existing behavior and API/auth/routing/polling code were kept outside the visual adjustments. See `CHANGELOG.md` for the source-path scope and verification limits.
