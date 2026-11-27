# CyberGuard X — Existing Frontend UI Documentation

**Source scope:** `frontend/` source tree as inspected on 2026-11-25. This document describes what is implemented in source, not backend behavior inferred beyond the API client/UI. No application source was modified. This documentation file is the only added file.

## 1. Project frontend overview

CyberGuard X is a Vite + React single-page application. `frontend/src/main.jsx` mounts `App` into `#root`; `App.jsx` owns authentication, the application shell, page selection, cross-page state, the WebSocket, global keyboard shortcuts, notices, and modal overlays. Ten page components are lazy-loaded. There is no React Router configuration, route table library, separate page URL, registration screen, or distinct admin dashboard in the frontend source.

Navigation state is encoded in the URL hash as `#overview`, `#live`, `#incidents`, `#threats`, `#explain`, `#assistant`, `#data`, `#evaluation`, `#agent`, or `#approvals`. The root pathname serves all states. Hash changes support browser back/forward; valid page state is also stored in session storage under `cyberguardx_active_page`. Unknown hashes fall back to a saved valid page or `overview`.

Authenticated shell: left sidebar + top header + notices + scrollable central workspace. The application uses dark SOC styling, Tailwind utilities, local CSS variables, Recharts, Phosphor icons, and GSAP motion helpers. The HTML document title is defined in `frontend/index.html`; no route-specific document title is set. No page footer is present in the application shell or page implementations inspected.

## 2. Complete page and route inventory

All entries below render inside the same authenticated shell and use the same application root URL/hash. “Access” identifies implemented navigation paths, not backend authorization guarantees.

| Page/screen | Hash route | Source | Purpose | Access | Layout |
|---|---|---|---|---|---|
| Analyst sign in | No page hash; root pathname | `frontend/src/components/LoginScreen.jsx`, rendered by `App.jsx` | Authenticate an assigned analyst | Unauthenticated initial state, logout, or session expiry | Full-screen split desktop login; compact stacked/mobile layout |
| Overview Dashboard | `#overview` | `frontend/src/pages/Overview.jsx` | Executive risk, category distribution, latest detection rows | Default page; sidebar; command palette; keyboard `g` then `o` | Auth shell and centered responsive dashboard grid |
| Live Monitoring / Live Feed | `#live` | `frontend/src/pages/LiveMonitoring.jsx` + `.css` | Search, filter, inspect and investigate event telemetry | Sidebar; command palette; `g` then `l` | Auth shell; full-width card/table; right-side event drawer |
| Incident Management | `#incidents` | `frontend/src/pages/IncidentManagement.jsx` | Correlate and triage incidents, inspect evidence, add notes and invoke investigation | Sidebar; command palette; `g` then `i` | Auth shell; incident list/work area with detail drawer/side panel |
| Threat Intelligence | `#threats` | `frontend/src/pages/ThreatIntelligence.jsx` | Review known/novel detections and visualized ATT&CK/open-set data | Sidebar; command palette; `g` then `t` | Auth shell; tabs within the page |
| Explainability | `#explain` | `frontend/src/pages/Explainability.jsx` | View incident risk/model explanation and deterministic investigation | Sidebar; command palette; `g` then `e` | Auth shell; incident selector and analysis panels, report drawer |
| AI Assistant | `#assistant` | `frontend/src/pages/AIAssistant.jsx` | Chat about incident evidence and retrieved threat knowledge | Sidebar and command palette for non-viewers; `g` then `a` except viewer | Auth shell; full-height chat panel |
| Data & Models | `#data` | `frontend/src/pages/DataManagement.jsx` | Inspect models/datasets, run replay/evaluation, load demos, upload logs | Sidebar; command palette; `g` then `d` | Auth shell; vertically stacked governance/control cards |
| Evaluation Summary | `#evaluation` | `frontend/src/pages/Evaluation.jsx` | Compare open-set metrics by profile and detector | Sidebar; command palette; `g` then `v` | Auth shell; metric selector controls and responsive comparison tables/charts |
| Agent Investigation Runs | `#agent` | `frontend/src/pages/AgentRuns.jsx` | Inspect agent execution timeline and report | Sidebar; command palette | Auth shell; run selector then two-column timeline/report |
| Action Approvals | `#approvals` | `frontend/src/pages/ApprovalsQueue.jsx` | Human review of proposed actions; approval records dry run only | Sidebar; command palette | Auth shell; vertically stacked proposal cards |

Other rendered screens/states without routes: command palette dialog; keyboard-shortcuts dialog; notifications popover; event detail drawer; incident detail panel; agentic investigation report panel; loading fallbacks; empty/error notices and error boundary. These are overlays or states, not separate routes. No route for signup, user administration, or backend admin console is present. `createAnalyst` exists in the API client but has no UI call site found.

## 3. Detailed page-by-page UI documentation

### 3.1 Analyst sign in

- **Visible content:** desktop left brand/marketing area with “See the signal. Secure what matters.” and CyberGuard X identity; right glass-style form card. On narrow screens, a compact brand block moves into the form and the split marketing presentation is hidden.
- **Form:** Username text input (`autoComplete=username`, required); Password (`type=password`, `autoComplete=current-password`, required); full-width “Sign in” button, changing to “Signing in…” and disabled during submission. Error is shown when login rejects. No registration, forgot-password, or cancel control is rendered.
- **Behavior:** submit calls login; on success token and analyst are saved to session storage and the authenticated shell replaces the form. Password input is cleared. Session expiry returns here and shows “Your session expired. Please sign in again.”
- **Assets:** ShieldCheck and ArrowRight icons; no external image asset is referenced by the screen source.
- **Unknown:** exact desktop column ratios and any identity-provider flow are not implemented/verified beyond classes and client API.

### 3.2 Overview Dashboard (`Overview.jsx`)

- No page-level `h1` is rendered; top shell header reads **“Executive Overview Dashboard.”**
- Starts with four KPI/stat cards (data-driven from dashboard stats; values/labels are selected from response properties in the component). Loading state skeletons reserve four cards, two chart cards, three smaller cards, and the results table.
- Main visual row: **Enterprise Risk Score Trend (Last 60 Min)** area/line chart (risk plotted over recent incident scores; responsive Recharts axes/grid/tooltip) beside **Threat Category Breakdown**, a donut chart with total in center and up to four category legend chips. Hovering a donut segment changes emphasis and tooltip.
- Three additional compact summary tiles/cards sit below the chart row (their displayed labels and numbers are populated from dashboard stats; see source response mapping; no independent controls).
- **Recent Detection Results** card contains a horizontally scrollable table with Verdict, Threat Category, Layer, Score, Attack Probability (24-tick indicator), Open-Set Distance, Timestamp. Up to eight alerts are fetched. New detection rows receive a brief highlight animation.
- Empty chart/table states use `EmptyState`; initial load uses skeletons; load failure produces unavailable messaging when data is missing. Data fetches dashboard stats and alerts, then separately incident data to derive the risk trend. No page-local filters, pagination, or modal.
- Row contents are informational; incident selection callback is passed from shell where applicable to page content components, but no row click is implemented in this table.

### 3.3 Live Feed (`LiveMonitoring.jsx`)

- Heading **Live Feed**; subtitle “Streaming security telemetry from connected layers.”
- Search control with placeholder “Search user, device, IP, type...”; matching is case-insensitive over user ID, device ID, source IP, and event type. `/` focuses search when focus is not already in an editable control; clear-search X control appears when query exists.
- Category filter buttons for All, Auth, Endpoint, Network, Access, with dynamic event counts. Keyboard behavior is attached to the filter group (see source); selection filters locally.
- Main card title **Continuous Security Telemetry Stream** and connection/live indicator. Data merges up to 100 initial events from `GET /events` with WebSocket security events; duplicate IDs resolve in favor of live rows. New events are briefly highlighted. Table columns: Timestamp; User / Identity; Device / Host; Network IP (source → destination); Event Type; Layer; Dataset; Status; unlabeled quick-action column.
- Event row is keyboard/click activatable and opens a right-side **Event details** drawer. The drawer shows “Read-only event record”, event type/ID, every key/value in the selected event, per-field Copy control (shows “Copied”), close X, and footer **Investigate with AI**. Quick action in the table has the same investigate label.
- Empty state distinguishes unavailable initial data, no received events, and no filter matches. API loading is represented by skeleton rows. Error state is reflected in empty-state wording; no pagination.
- Investigation action selects the AI Assistant and passes an initial prompt with event telemetry wrapped as untrusted content. The drawer remains an overlay until navigation/unmount.

### 3.4 Incidents (`IncidentManagement.jsx`)

- Heading **Incidents**. Top card section **Rule-based cross-layer correlation** describes the deterministic correlation operation and offers its run action; window is called with 60 minutes. Correlation success/error status is displayed inline.
- **Correlated incidents** area shows incident records with severity/status badges, identifiers, timestamps and summary fields. Loading uses skeletons; empty and error presentations are explicit. The list can be filtered by controls present in source (severity and status filters); verify exact option labels directly in the component source when customizing an individual detail.
- Selecting an incident opens its detailed panel. The panel includes incident title/ID/status/severity, timestamps, involved identities/devices and event/evidence data where provided; model score summary; attack sequence; risk component breakdown; rule indicator alerts; and notes. Buttons change incident status and add a note. A textarea placeholder reads “Add triage note, containment action, or forensic finding...”.
- Available incident actions include AI Assistant handoff and agent investigation launch for roles other than `viewer`; callbacks are passed as `null` to viewer. Agent action starts a run and moves to Agent Runs with returned run ID. Notes are submitted to the incident notes endpoint. The source uses a side drawer/modal for details.
- **Unknown:** source API provides fields dynamically; no client-side field schema is specified for all incident/evidence records. No pagination was found in the incident list.

### 3.5 Threat Intelligence (`ThreatIntelligence.jsx`)

- Heading **Threat Intelligence**. Tablist: **Threat intelligence**, **MITRE ATT&CK**, **Distance map**. Selecting Distance map lazily marks the view opened and renders the map component.
- Threat intelligence view begins with **Unknown / Novel Threat View**, explanatory open-set text, and novel alert records. A record presents verdict badge, event/detection ID with copy control and “Copied” feedback, timestamp, and scored metadata available in response.
- Below are two side-by-side cards: **Classified Known Attack Families** (CICIDS2017 LightGBM classifier) and **Unconfirmed Candidate Queue** (flows rejected by known-validation score threshold, needing analyst review). Candidate entries show “Unconfirmed candidate”, shortened event ID, latent distance, reconstruction error, and timestamp. Empty state “No unconfirmed candidates”.
- **MITRE ATT&CK** tab embeds `MitreMatrix`: mapped techniques grouped by tactic, incident counts, selected-technique panel and linked incidents; technique buttons toggle selection and “Clear selection” resets it. On failure a retry panel appears with retry countdown/button.
- **Distance map** tab embeds `DistanceMap`: open-set detections positioned by recorded distance, verdict toggles/legend with counts, tooltip on plotted points. The chart source uses its own alert endpoint fetch; loading/error/empty behavior is component-defined.
- Initial threat data loads `GET /threats` and `GET /alerts?verdict=UNKNOWN_NOVEL&limit=100`. No paging controls are present.

### 3.6 Explainability (`Explainability.jsx`)

- Shell heading **“SHAP Explainability & Risk Scoring.”** Page content section heading **Multi-modal explainability**, subtitle “Unified risk, model contributions, and stored branch evidence.”
- Incident dropdown labeled for incident selection. Initial load obtains incidents and, if available, selects first incident and requests explainability. Selecting another incident refreshes explanation. Empty/error content when no incident or fetch failure.
- Panels include unified risk/score display, model branch contributions, **TreeSHAP feature attributions** with signed values and note that signs indicate raising/lowering predicted class score, and **Open-set novelty** metrics. Data values are rendered from the selected incident explanation response.
- Action opens a side **Agentic investigation report** modal/drawer. It is identified as **Read-only workflow** and displays stages (“retrieve → analyze → map → summarize → recommend”), returned data, evidence and recommendations supplied by `investigateIncident`; close button/X. Investigation is deterministic API call, not the agent run flow.
- Exact chart type/field list varies with response and component conditionals; no pagination or form submission exists.

### 3.7 AI Security Assistant (`AIAssistant.jsx`)

- Shell heading **“Grounded AI Security Assistant (RAG).”** Chat card top bar: **Grounded SOC Investigation Assistant** and “FAISS Vector Search & Evidence Citations (Read-Only Guardrail)”.
- Context dropdown label **Incident Context:** with “General Threat Intelligence” empty option and incident titles/short IDs. Messages are aligned user-right/assistant-left; avatar icons User/Bot; assistant mode badge; retrieved source chips show chunk ID, title and score. Expandable **Stored evidence used** JSON details when present.
- Empty states: no incident records (“No incident selected” and load/select guidance, plus optional incident load error); incident records but empty selected context (“Select an incident to begin”). Retrieval errors appear above messages. While submitting, spinner text says “Analyzing incident evidence and retrieving ATT&CK techniques...”.
- Quick prompt buttons: “What attack technique might be involved?” and “What are the recommended containment steps?” (disabled without selected incident or while loading). Text input placeholder and aria label ask about anomalies, attack classification or containment; **Send** disabled when blank/no incident/loading.
- Sends `POST /rag/chat` with query and selected incident ID. Initial incident/prompt can be passed from Overview/Live or incident handoff. Page height uses `calc(100vh - 190px)` with 520px minimum. No conversation persistence or pagination implemented in visible component state.

### 3.8 Data & Model Training (`DataManagement.jsx`)

- This is a vertically stacked operational/governance page; browser shell title **“Data Governance & Model Training.”** Cards show model status, dataset status, evaluation outputs, demo replay and upload controls. Role is passed in; uploader/training controls reflect source role conditionals (not a separate admin route).
- Evaluation/model result subviews include tables. Per-class metrics columns: Class, Precision, Recall, F1, Support. Open-set detector comparison columns: Detector, AUROC ↑, FPR@95% ↓, Unk Rejection ↑, Known FalseReject ↓; another comparison includes Threshold. Missing evaluation/model data is handled with component-specific blank messaging.
- **Held-out CICIDS replay:** numeric Rows input default `3000`, minimum 1; numeric Rows / sec default `10`, minimum 0; replay start/stop controls, status/progress fields and periodic replay status poll. Start submits `n` and `speed`; stop halts replay.
- **Synthetic correlation scenarios:** load-demo action; displays result/status and emits a synthetic-demo-updated event to refresh shell banner.
- **Security Telemetry Upload:** hidden file input with visible label/drop area; file submitted as multipart field `file` to `/api/upload`; displays outcome/error. Exact accept/file extensions depend on input attribute in source; client validation is not otherwise defined.
- **ML Model Weights & Governance:** status/metadata display and trigger-evaluation button. Evaluation run trigger polls job status until terminal state. The only visible inputs associated with this page are the two replay numeric inputs and file input; no model weights editor form is defined.
- API loading uses parallel calls to models status, CICIDS status and evaluation results; secondary fetch failures for CICIDS/evaluation are converted to null. Replay is polled. Error/success messages are local to the page. No pagination.

### 3.9 Evaluation Summary (`Evaluation.jsx`)

- Shell heading **CICIDS Evaluation Summary**; page heading **Open-set evaluation metrics**. Fetches `GET /evaluation/summary`.
- Repeated profile sections show profile name and metric selector pills. Available metric names are defined in component source; selecting a pill updates that profile’s displayed metric/chart. Data is grouped by detector/profile as returned.
- Comparison table uses sticky Detector first column and dynamically generated attack-family columns. Values use a heatmap/tone cell presentation; horizontal scrolling retains detector column. Responsive chart/table container.
- Fetch error and missing-summary states are rendered in-page; no reload action, pagination, or modal is defined in the page. Metric selection is local UI state only.

### 3.10 Agent Investigation Runs (`AgentRuns.jsx`)

- Heading **Run timeline and report**, eyebrow **Agentic investigations**, advisory subtitle. Error banner may appear above a **Choose a run** select. Option labels contain incident ID, status, and started timestamp/“queued”. Empty option displays “Loading runs…” or “No runs available”.
- Selected-run summary card shows run ID, incident ID, agent ID, status badge, model name, mode, LLM calls, tool calls.
- Two-column desktop content: **Step timeline** list (step number, kind, tool name, OK/Error, duration, result summary, evidence ID chips); and **Investigation report** (assessment, summary, key findings, ATT&CK mapping table [Technique, Rationale, Evidence], hypotheses with Supports/Contradicts IDs, missing evidence, limitations, proposed actions, validation status).
- Empty timeline says “Waiting for the first step…” when queued/running or “No steps were recorded.” Otherwise. Fallback/limit warnings are conditionally shown. **Compare with deterministic baseline** toggles a JSON baseline section and fetches it once; label changes to **Hide deterministic baseline**. Active runs refresh every 1.5 seconds. Error text surfaces run/list/baseline fetch failures.

### 3.11 Action Approvals (`ApprovalsQueue.jsx`)

- Heading **Action approvals**, eyebrow **Human review**, note “Each action needs a human decision. Approval records a dry run only.”
- Loads pending agent proposals and agent config. Each proposal card shows proposal ID, incident ID, action type, target type and target, rationale, evidence IDs and status/context where returned. Self-approval restrictions are derived from agent config/current analyst and disable controls with a title explanation.
- Optional **Decision note** textarea, maxLength 1000, two rows, placeholder “Optional note for the audit trail”. Buttons **Approve · simulate** and **Reject**. Submit calls respective API; status refresh and inline errors follow. Approval is presented as simulated/dry-run only.
- Empty pending queue state is shown when no proposals. No pagination or proposal detail modal.

## 4. Complete navigation hierarchy

```text
CyberGuard X
├─ Operate
│  ├─ Overview              #overview
│  ├─ Live Feed             #live
│  └─ Incidents             #incidents
├─ Investigate
│  ├─ Threats               #threats
│  ├─ AI Assistant          #assistant (hidden for role=viewer)
│  ├─ Explainability        #explain
│  ├─ Agent Runs            #agent
│  └─ Approvals             #approvals
└─ Platform
   ├─ Data & Models         #data
   └─ Evaluation            #evaluation
```

Navigation uses sidebar buttons (not anchor links) and Header command palette. Page titles are centrally mapped in `App.jsx`: Executive Overview Dashboard; Live Security Telemetry Stream; Incident Management & Correlation; Threat Intelligence & Open-Set Analysis; SHAP Explainability & Risk Scoring; Grounded AI Security Assistant (RAG); Data Governance & Model Training; CICIDS Evaluation Summary; Agent Investigation Run; Human Action Approvals.

No breadcrumbs are rendered. Subnavigation exists only as Threat Intelligence tabs and local incident/event/run selects. Internal flows: Live event “Investigate with AI” → assistant with telemetry prompt; incident AI handoff → assistant with incident context; incident agent investigation → creates run then Agent Runs with returned run ID. Overview and Explainability can hand incident context into assistant/report flows.

Global keyboard controls while authenticated: `Ctrl/Cmd+K` opens palette; `?` opens Keyboard shortcuts dialog; `[` toggles sidebar; `g` then `o/l/i/t/e/a/d/v` navigates to Overview/Live/Incidents/Threats/Explainability/Assistant/Data/Evaluation (900ms prefix timeout; assistant shortcut blocked for viewer). Live page `/` focuses search. Sidebar supports ArrowUp/ArrowDown/Home/End roving focus. Escape closes modal, palette, and mobile sidebar as implemented.

Header notifications button opens a popover listing high-severity live events and can navigate to Live Feed. Header search opens command palette. No breadcrumb component or footer navigation is present.

## 5. Reusable component inventory

| Component/file | Purpose and visible behavior |
|---|---|
| `components/Sidebar.jsx` | Grouped primary nav, collapse-to-icon rail, mobile slide-in, badges for unread live events/critical incidents, engine/WebSocket/last-updated status, analyst username/role and logout. Props: activePage, setActivePage, role, liveEventsCount, wsConnected, analyst, onLogout. Persists collapsed setting in localStorage; refreshes dashboard stats at 30s cadence. |
| `components/Header.jsx` | Current page title, motion preference toggle, search/command palette button, high-severity notifications popover, WebSocket status and analyst identity/role. Receives pageTitle, wsConnected, analyst, onLogout, liveEvents, role, setActivePage, commandPaletteOpen, setCommandPaletteOpen. The current Header rendering does not expose its `onLogout` prop; logout control is in Sidebar. |
| `components/LoginScreen.jsx` | Controlled username/password sign-in form; props for values/setters/error/pending/submit callback. GSAP magnetic button hover. |
| `components/CommandPalette.jsx` | Dialog search over pages, incidents and MITRE techniques; keyboard navigation/selection, grouped result options; calls incident fetch. Uses Modal. |
| `components/ErrorBoundary.jsx` | Catches render failures per active page; displays error message, console hint and **Try again**. `resetKey` is page ID. |
| `components/RiskFusion.jsx` | Incident risk component visualization used by incident details; renders component scores/combined risk using props supplied by parent. |
| `components/MitreMatrix.jsx` | ATT&CK tactic/technique grid, incident counts, selected technique and linked incident detail, retryable error state. Fetches incidents itself. |
| `components/viz/DistanceMap.jsx` | Open-set scatter/distance visualization, verdict class toggles/counts, tooltips; requests alerts by verdict. |
| `components/viz/FlowOrb.jsx` | Decorative/visual flow/orb graphic used by Overview. |
| `components/ui/Modal.jsx` | Accessible dialog overlay or right-side panel. Props `open`, `onClose`, `title`, `children`, `side`, `className`; Escape/backdrop close; focus moves in and returns; Tab focus is trapped. |
| `components/ui/Card.jsx` / `GlassCard.jsx` | Semantic section wrapper with SOC panel styles. Props `as`, `className`, children, remaining DOM props. |
| `components/ui/Badge.jsx` (also re-exported as `Pill.jsx`) | Severity/status pill; tones critical/high/medium/low/normal/novel/neutral. Props tone/className/children/DOM props. |
| `components/ui/Button.jsx` | Button with primary/ghost/danger variants; children, variant, className and native button props. Global CSS flattens gradients into palette colors. |
| `components/ui/PillButton.jsx` | Button alias with secondary mapped to ghost; passes props to Button. |
| `components/ui/StatCard.jsx` | Animated numeric statistic card; label, value, formatValue, detail, className. Honors reduced motion. |
| `components/ui/StatTile.jsx` | Compact label/value/icon/tone/detail tile. |
| `components/ui/Table.jsx` | Table/TableHeader/TableBody/TableRow/TableCell wrappers; horizontal overflow, sticky header, styled rows/cells. |
| `components/ui/Input.jsx` | Forward-ref styled input; className plus standard input props. |
| `components/ui/Toggle.jsx` | Accessible switch button; checked, onChange, label, disabled, className. |
| `components/ui/Skeleton.jsx` | Pulsing placeholder div; className and DOM props. |
| `components/ui/EmptyState.jsx` | Optional icon/title/description/children empty-state panel. |
| `components/ui/ErrorState.jsx` | Alert block with title/description and optional **Try again** callback. |
| `components/ui/SectionHeader.jsx` | Title/description with optional trailing action. |
| `components/ui/RiskTicks.jsx` | 24 vertical risk ticks and optional numeric percentage; clamps visual scale to 0–100. Props value, className, showValue, suffix. |
| `components/ui/Tooltip.jsx` / `GlassTooltip.jsx` | Hover/focus tooltip wrapper with label and children. |
| `components/ui/cn.js` | Class-name composition utility, not a visible component. |
| `charts/ChartTooltip.jsx` | Shared chart tooltip component. |
| `charts/chartTheme.js` | Shared chart grid/axis/tooltip colors and palette. |
| `lib/icons.js` | Phosphor icon aliases used across UI. |
| `lib/motion.js` | Reduced-motion settings and GSAP motion scope utilities. |

The two helpers nested inside `AgentRuns.jsx` (`EvidenceChips`, `Section`) and page-local chart/format helpers are not separately exported reusable components.

## 6. Forms and interactions documentation

| Form/control | Fields/default/validation | Actions/results |
|---|---|---|
| Sign in | Username string required; Password password input required; empty default values. Browser `required`; no custom rules visible. | Sign in → `POST /auth/login`; error inline; success persists token/analyst in sessionStorage, clears password and opens shell. |
| Live search | Text, initial empty; no required rule. | Local case-insensitive filter over user, device, source IP, event type; clear button; `/` shortcut. |
| Live category filters | Five category buttons; initial `all`. | Local filter and counts update; not sent as API query after initial fetch. |
| Event detail drawer | No form. Dynamic fields are copied individually using Clipboard API. | Close via X, Escape, backdrop; **Investigate with AI** transfers event context to assistant. |
| Incident filter/correlation | Severity/status selectors are local state; correlation uses fixed 60-minute parameter. | Run correlation triggers POST; select row opens detail; status buttons PATCH; note textarea POST; assistant/agent handoff. |
| Assistant | Incident select initial from handoff or empty; query text initially empty. | Quick prompts call same send handler. Send disabled if query blank, no incident or loading; POST RAG; message list displays returned response/mode/sources/evidence. |
| Data replay | Rows number default 3000, min 1; Rows/sec number default 10, min 0. | Start replay POST; Stop POST; status polled; errors/status shown. |
| Upload | File input, single selected `file`; no explicit required/size validation beyond input/browser and server response. | Multipart POST `/upload`; shows result/error. |
| Data demo/evaluation | No user fields for load scenarios/evaluation trigger. | Load scenarios POST; evaluation run POST then status polling. |
| Evaluation metrics | Metric-selection buttons per profile; initial selection from component default. | Local display selection; no network request per click. |
| Agent run selection | Select run ID; no validation. | Fetch run; active queued/running run is polled every 1.5 sec. Baseline button fetches deterministic investigation once, toggles JSON display. |
| Approval decision | Decision note optional, max 1000 chars, two-row textarea, no other validation. | Approve · simulate / Reject submit note to corresponding endpoint; controls disabled when policy disallows self-approval; refreshes proposal list/result. |
| Header motion toggle | No field; reflects system/user reduced motion preference. | Toggles motion setting and dispatches change event; reduced motion also follows OS preference. |
| Command palette | Search text; initial empty; no validation. | Filters pages/incidents/techniques, arrows select, Enter activates, Escape closes. |
| Keyboard shortcuts modal | No form. | `?` opens, Esc/close control closes. |

No pagination control is implemented in page sources reviewed. Tables generally use horizontal scrolling and sticky headings; live/overview tables have bounded vertical scroll regions.

## 7. API and data dependency documentation

Base URL is `/api`. `fetchJson` sends JSON content type and, when present, `Authorization: Bearer <session token>`. HTTP errors parse `detail` into text and throw; 401 (except login) clears token/analyst and dispatches session-expired; 403 dispatches analyst-forbidden and the shell displays a dismissible 403 banner. Upload uses `FormData` and bearer auth without setting JSON content type. The frontend source can verify endpoint and method but not backend response schema beyond fields accessed below.

| Endpoint | Method | UI use and fields accessed |
|---|---|---|
| `/auth/login` | POST `{username,password}` | Sign in; `access_token`, `analyst` (`username`, `role` used). |
| `/auth/me` | GET | Refresh analyst object; username/role used in shell. |
| `/auth/users` | POST `{username,password,role}` | Client wrapper exists; no frontend UI call site found. |
| `/demo/status` | GET | Shell checks `has_synthetic_demo`; polled every 15 seconds and on synthetic-demo-updated. |
| `/demo/load` | POST | Data page loads synthetic correlation scenarios. |
| `/demo/replay` | POST `{n,speed}` | Data page replay with row count and rate. |
| `/demo/replay/status` | GET | Replay state/progress polling. |
| `/demo/replay/stop` | POST | Stop replay. |
| `/dashboard/stats` | GET | Overview KPI/risk trend and Sidebar system status/critical incident count. Sidebar accesses `system_status`, `critical_incidents`; page accesses mapped KPI/chart fields. |
| `/events?category=&limit=` | GET | Live initial events (`limit=100`, empty category); table reads event_id, timestamp, user_id, device_id, source_ip, destination_ip, event_type, event_category/category, dataset, status. |
| `/ws/live-events?token=` | WebSocket | Authenticated stream. `SECURITY_EVENT` messages are retained (max 151) and feed Live page/header. 4401 dispatches expiry; other close reconnects after 3 sec. |
| `/alerts?verdict=&limit=` | GET | Overview recent alerts (`limit=8`); threat page novelty (`UNKNOWN_NOVEL`, 100); DistanceMap verdict batches (500). UI reads detection_id, event_id, verdict, predicted_class, layer, score, attack_probability, open_set_distance, created_at, timestamp, reconstruction_error and other rendered record values. |
| `/threats` | GET | Threat known-family and unknown-candidate data; UI accesses returned list/count/class/distance fields conditionally. Exact complete response schema is unknown from frontend. |
| `/incidents?severity=&status=` | GET | Incident list, Assistant choices, Overview risk data, MITRE matrix, Command Palette. Query args only included when supplied. UI uses incident_id, title, severity, status, timestamps, summary/evidence fields. |
| `/incidents/{id}` | GET | Incident detail. Exact full response schema unknown. |
| `/incidents/{id}/status?status=` | PATCH | Change incident status; status query URL-encoded. |
| `/incidents/{id}/notes` | POST `{content,author:"SOC Analyst"}` | Add incident note. |
| `/correlation/run?window_minutes=60` | POST | Incident correlation action. |
| `/explainability/{id}` | GET | Explainability page; field-level model/SHAP/novelty properties read from returned object. Full schema unknown. |
| `/incidents/{id}/investigate?top_k=6` | POST | Explainability report and agent baseline comparison; returns deterministic investigation data. |
| `/agent/config` | GET | Incident and approvals policy; `allow_self_approval` is accessed. |
| `/incidents/{id}/agent-investigate` | POST | Start agent run; `run_id` used to navigate to Agent Runs. |
| `/agent/runs?incident_id=&limit=` | GET | AgentRuns requests limit 50 and empty incident ID; options use run_id, incident_id, status, started_at. |
| `/agent/runs/{run_id}` | GET | Run details. UI uses agent_id, status, model_name, mode, usage.llm_calls/tool_calls, steps, report, validation. |
| `/agent/runs/{run_id}/cancel` | POST | API wrapper exists; no visible call site found. |
| `/agent/proposals?status=pending&incident_id=` | GET | Pending approval queue; proposal identity/action/target/rationale/evidence/status fields are conditionally rendered. |
| `/agent/proposals/{id}/approve` | POST `{note}` | Approve/simulate proposal. |
| `/agent/proposals/{id}/reject` | POST `{note}` | Reject proposal. |
| `/rag/chat` | POST `{query,incident_id}` | Assistant chat; frontend uses returned answer text, mode, sources (`chunk_id`, `title`, `score`), evidenceUsed. Exact schema unknown. |
| `/models/status` | GET | Data & Models status/weights metadata; exact response schema unknown. |
| `/datasets/cicids` | GET | CICIDS dataset state; exact response schema unknown. |
| `/upload` | POST multipart `file` | Telemetry upload; response fields rendered based on result. |
| `/analyze` | POST event data JSON | Wrapper exists; no UI call site found. |
| `/evaluation/summary` | GET | Evaluation Summary profiles, detectors, metrics and family data. |
| `/evaluation/results` | GET | Data page saved evaluation result tables. |
| `/evaluation/run?force_reload=&seed=&sample=&log1p=` | POST | Data page calls defaults `false,42,1,false`; returns `job_id`. |
| `/evaluation/status/{job_id}` | GET | Data page polls evaluation status. |

No API secrets or credentials are documented. Frontend code does not specify endpoint server origin (proxy/routing is configured outside `api.js`); `vite.config.js` and deployment nginx config exist, but deployment environment values are not treated as secrets or copied here. Loading/error UX varies by page as described above; most pages log fetch failures to console and display inline error/empty UI. No API response JSON fixtures are used to define a complete guaranteed schema.

## 8. Existing design and styling specifications

Primary design tokens are in `frontend/src/index.css`:

| Token | Value |
|---|---|
| Background | `#000000` |
| Raised surface/workspace | `#131209` |
| Panel | `#181818` |
| Card | `#1f1f1f` |
| Hover | `#272727` |
| Border | `#313131`; soft border `rgba(255,255,255,0.09)` |
| Main text | `#f4f4f4`; muted `#c2c2c2`; subtle `#9b9b9b` |
| Critical/high/medium/low/normal/novel | `#e94759` / `#ed8b46` / `#e8b84c` / `#3b82f6` / `#20c997` / `#b66bea` |
| Accent | `#3b82f6` |
| Font display/body | Manrope Variable, sans-serif |
| Monospace | JetBrains Mono |
| Radius tokens | 0.25rem / 0.5rem / 0.75rem / 1rem for sm/md/lg/xl |
| Page/card spacing tokens | 1.5rem / 1rem (mobile page token becomes 1rem) |
| Panel shadow | `0 12px 32px rgba(19,18,9,.3)` plus subtle inset highlight |

Global card treatment uses a dark panel, soft 1px border and panel shadow. Workspace is raised `#131209`, rounded, bordered. Sidebar is raised with right border; selected page gets `#272727`, border and blue inset marker. Header is black with subtle border. Table rows use subtle white overlays, rounded first/last cells and hover fill. Global grain overlay is a noninteractive fixed SVG turbulence layer at 3.5% opacity. Scrollbar is 7px, dark track/thumb. Focus-visible is a 2px blue outline.

Typography classes `heading-1..6` map to Tailwind sizes 6xl/5xl/4xl/3xl/2xl/xl; display headings use Manrope; data IDs use JetBrains Mono and tabular numerals. `index.css` normalizes arbitrary utility text sizes into common values (e.g. classes 9–12px become 12px, 13–15px become 14px, 36/38px become 36px). Thus authored class numbers can differ from computed result. Many components set responsive spacing with Tailwind `sm`, `md`, `lg`, `xl` modifiers.

Tailwind standard breakpoints are used (config extends colors/fonts/theme; inspect `frontend/tailwind.config.js` for the declared extension list). Explicit behavior in source: body min-width 320px; mobile sidebar at max 767px becomes off-canvas 16rem drawer with backdrop/open button; medium desktop sidebar collapses by default at max 1023px; desktop sidebar widths 4rem collapsed or 250px expanded. Workspace and cards use smaller radius at max 767px. Overview and tables switch grids at sm/md/lg/xl; wide tables scroll horizontally. AgentRuns becomes two columns at xl. Login stacks at mobile. No tablet-specific alternate content layout beyond these responsive utility rules.

Motion: GSAP entrance/row animations; reduced motion follows OS and toggle state via `lib/motion.js`, and CSS disables animation/transitions when reduced. `LiveMonitoring.css` animates new rows and live pulse. The actual card dimensions vary by content; fixed/min heights in source include overview chart cards `22rem`, KPI loading card `min-h-36`, assistant min height 520px, and responsive max widths up to 1500/1600px. No image asset inventory is referenced by page layouts; icons are Phosphor React SVG components. Overview uses Recharts SVG charts.

## 9. Responsive behavior documentation

- Root shell fills `100dvh`, width `100vw`, hides outer overflow; main content scrolls vertically and page containers own horizontal table/chart overflow.
- Sidebar: mobile (<768px) is a fixed left drawer with scrim, open/close buttons and Escape support; >=768px uses sidebar in shell. Collapsed state persisted in localStorage; on widths through 1023px initial default is collapsed unless stored preference overrides it.
- Main padding grows from `p-3` to `sm:p-4` to `lg:p-5`; workspace inner padding grows `p-4`, `sm:p-6`, `lg:p-8`.
- Cards/grids wrap or collapse according to Tailwind classes: overview 1 column → 2 at sm → 4 KPI at lg; chart section up to 3 columns at lg with trend spanning 2; tables scroll horizontally at their min widths. Live search/filter controls wrap; chat header wraps; agent report columns appear at xl.
- Login hides desktop promo panel at mobile and shows compact brand in form.
- Explicit page fixed-height content: assistant chat uses viewport height minus 190px, min 520px; event/investigation side panels cap to viewport and scroll internally.
- CSS body minimum width is 320px. No dedicated tablet screenshots or runtime browser measurements are part of source-only inspection; exact pixel-perfect wrapping at each device width is unknown.

## 10. Authentication and role-based UI

- Login uses `POST /api/auth/login`; successful result stores access token and analyst JSON in `sessionStorage` (`cyberguardx_access_token`, `cyberguardx_analyst`). There is no refresh-token flow in frontend source.
- On app initialization, saved token and analyst are read. If a token is present, `GET /api/auth/me` refreshes analyst info (failure is swallowed). Authenticated API calls attach bearer token. 401 clears saved token/analyst and dispatches `analyst-session-expired`; app clears auth and displays session-expired login message. Logout clears token and analyst and switches to login.
- Protected screen enforcement is shell-level (`!authToken` returns only LoginScreen). There are no per-route guards because routes are hash states, not router routes. Backend responses remain authoritative for API authorization; 403 appears as dismissible shell banner.
- Analyst role appears in sidebar profile. Role `viewer` hides AI Assistant from sidebar and blocks its `g,a` shortcut. Incident management receives null assistant/agent callbacks for viewer. Data page receives role and applies its source-level conditional controls. Approval availability/self-approval is additionally controlled by `allow_self_approval` from agent config and current analyst. Other endpoint authorization is not established solely by frontend code.
- No separate admin page, role management screen, registration screen, or explicit role matrix is implemented. `createAnalyst` is an unused API wrapper in current frontend call graph.
- Live WebSocket authenticates with token in query string; a 4401 close triggers session expiry. Other disconnects reconnect automatically.

## 11. Complete frontend file and folder structure

```text
frontend/
├─ Dockerfile
├─ index.html
├─ nginx.conf
├─ package.json
├─ package-lock.json
├─ postcss.config.js
├─ tailwind.config.js
├─ vite.config.js
├─ MOTION_AND_DESIGN_NOTES.md
└─ src/
   ├─ App.jsx
   ├─ main.jsx
   ├─ index.css
   ├─ charts/
   │  ├─ ChartTooltip.jsx
   │  └─ chartTheme.js
   ├─ components/
   │  ├─ CommandPalette.jsx
   │  ├─ ErrorBoundary.jsx
   │  ├─ Header.jsx
   │  ├─ LoginScreen.jsx
   │  ├─ MitreMatrix.jsx
   │  ├─ RiskFusion.jsx
   │  ├─ Sidebar.jsx
   │  ├─ ui/
   │  │  ├─ Badge.jsx
   │  │  ├─ Button.jsx
   │  │  ├─ Card.jsx
   │  │  ├─ EmptyState.jsx
   │  │  ├─ ErrorState.jsx
   │  │  ├─ GlassCard.jsx
   │  │  ├─ GlassTooltip.jsx
   │  │  ├─ Input.jsx
   │  │  ├─ Modal.jsx
   │  │  ├─ Pill.jsx
   │  │  ├─ PillButton.jsx
   │  │  ├─ RiskTicks.jsx
   │  │  ├─ SectionHeader.jsx
   │  │  ├─ Skeleton.jsx
   │  │  ├─ StatCard.jsx
   │  │  ├─ StatTile.jsx
   │  │  ├─ Table.jsx
   │  │  ├─ Toggle.jsx
   │  │  ├─ Tooltip.jsx
   │  │  └─ cn.js
   │  └─ viz/
   │     ├─ DistanceMap.jsx
   │     └─ FlowOrb.jsx
   ├─ lib/
   │  ├─ icons.js
   │  └─ motion.js
   ├─ pages/
   │  ├─ AIAssistant.jsx
   │  ├─ AgentRuns.jsx
   │  ├─ ApprovalsQueue.jsx
   │  ├─ DataManagement.jsx
   │  ├─ Evaluation.jsx
   │  ├─ Explainability.jsx
   │  ├─ IncidentManagement.jsx
   │  ├─ LiveMonitoring.css
   │  ├─ LiveMonitoring.jsx
   │  ├─ Overview.jsx
   │  └─ ThreatIntelligence.jsx
   └─ services/
      └─ api.js
```

This tree lists every file under `frontend/` returned by the source inventory, including build/deployment configuration and design notes. `package-lock.json` is intentionally shown but its generated package contents are outside UI inventory. Backend files are outside the requested frontend scope.

## Verification notes / known unknowns

This report was derived by reading the frontend source, not by exercising the app against a running backend. Exact values and row counts depend on API responses. Where frontend accesses response properties but source does not define server schemas, the schema is marked unknown. No claim is made about browser rendering beyond authored layout/style rules. A few highly conditional data cards use dynamic response labels/fields; their exact visible rows depend on backend payloads. No test/build was run because the task requested documentation only and did not ask for verification that would execute project code.
