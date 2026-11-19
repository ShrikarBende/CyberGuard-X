/**
 * Enterprise CyberGuard X - API Client Service
 */

const API_BASE = '/api';

function errorMessageFromResponse(detail, fallback) {
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => (
      typeof item === 'string' ? item : item?.msg || JSON.stringify(item)
    )).join('; ');
  }
  if (detail && typeof detail === 'object') return JSON.stringify(detail);
  return fallback;
}

async function fetchJson(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const token = window.sessionStorage.getItem('cyberguardx_access_token');
  const config = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  };

  try {
    const res = await fetch(url, config);
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      if (res.status === 401 && endpoint !== '/auth/login') {
        window.sessionStorage.removeItem('cyberguardx_access_token');
        window.sessionStorage.removeItem('cyberguardx_analyst');
        window.dispatchEvent(new Event('analyst-session-expired'));
      }
      if (res.status === 403) {
        window.dispatchEvent(new CustomEvent('analyst-forbidden', {
          detail: errBody.detail || 'Your role does not have permission to do that.',
        }));
      }
      throw new Error(errorMessageFromResponse(
        errBody.detail,
        `HTTP Error ${res.status}: ${res.statusText}`,
      ));
    }
    return await res.json();
  } catch (err) {
    console.error(`API call failed [${url}]:`, err);
    throw err;
  }
}

export const api = {
  login: (username, password) => fetchJson('/auth/login', {
    method: 'POST', body: JSON.stringify({ username, password }),
  }),
  getCurrentAnalyst: () => fetchJson('/auth/me'),
  createAnalyst: (username, password, role) => fetchJson('/auth/users', {
    method: 'POST', body: JSON.stringify({ username, password, role }),
  }),
  getDemoStatus: () => fetchJson('/demo/status'),
  loadDemoScenarios: () => fetchJson('/demo/load', { method: 'POST' }),
  runCorrelation: (windowMinutes = 60) =>
    fetchJson(`/correlation/run?window_minutes=${windowMinutes}`, { method: 'POST' }),
  startDemoReplay: (n = 3000, speed = 10) =>
    fetchJson('/demo/replay', { method: 'POST', body: JSON.stringify({ n, speed }) }),
  getDemoReplayStatus: () => fetchJson('/demo/replay/status'),
  stopDemoReplay: () => fetchJson('/demo/replay/stop', { method: 'POST' }),
  getEvaluationSummary: () => fetchJson('/evaluation/summary'),

  // 1. Dashboard KPIs
  getDashboardStats: () => fetchJson('/dashboard/stats'),

  // 2. Events & Live Monitoring
  getEvents: (category = '', limit = 50) => {
    const q = new URLSearchParams();
    if (category) q.set('category', category);
    q.set('limit', limit);
    return fetchJson(`/events?${q.toString()}`);
  },

  // 3. Alerts & Threats
  getAlerts: (verdict = '', limit = 50) => {
    const q = new URLSearchParams();
    if (verdict) q.set('verdict', verdict);
    q.set('limit', limit);
    return fetchJson(`/alerts?${q.toString()}`);
  },
  getThreats: () => fetchJson('/threats'),

  // 4. Incidents
  getIncidents: (severity = '', status = '') => {
    const q = new URLSearchParams();
    if (severity) q.set('severity', severity);
    if (status) q.set('status', status);
    return fetchJson(`/incidents?${q.toString()}`);
  },
  getIncidentDetail: (id) => fetchJson(`/incidents/${id}`),
  updateIncidentStatus: (id, status) =>
    fetchJson(`/incidents/${id}/status?status=${encodeURIComponent(status)}`, { method: 'PATCH' }),
  addIncidentNote: (id, note) =>
    fetchJson(`/incidents/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify({ content: note, author: 'SOC Analyst' }),
    }),

  // 5. Explainability
  getExplainability: (id) => fetchJson(`/explainability/${id}`),
  investigateIncident: (id, topK = 6) => fetchJson(`/incidents/${id}/investigate?top_k=${topK}`, { method: 'POST' }),

  // 6. RAG Chat Assistant
  ragChat: (query, incidentId = null) =>
    fetchJson('/rag/chat', {
      method: 'POST',
      body: JSON.stringify({ query, incident_id: incidentId }),
    }),

  // 7. Models & CICIDS2017
  getCicidsStatus: () => fetchJson('/datasets/cicids'),
  getModelsStatus: () => fetchJson('/models/status'),

  // 8. Ingestion & Upload
  uploadLogs: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const token = window.sessionStorage.getItem('cyberguardx_access_token');
    const res = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      body: formData,
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      if (res.status === 401) {
        window.sessionStorage.removeItem('cyberguardx_access_token');
        window.sessionStorage.removeItem('cyberguardx_analyst');
        window.dispatchEvent(new Event('analyst-session-expired'));
      }
      if (res.status === 403) {
        window.dispatchEvent(new CustomEvent('analyst-forbidden', {
          detail: errBody.detail || 'Your role does not have permission to do that.',
        }));
      }
      throw new Error(errorMessageFromResponse(errBody.detail, `Upload failed: ${res.statusText}`));
    }
    return await res.json();
  },
  analyzeEvent: (eventData) =>
    fetchJson('/analyze', {
      method: 'POST',
      body: JSON.stringify(eventData),
    }),

  // 9. CICIDS2017 Evaluation Results (read from JSON files, never hardcoded)
  getEvaluationResults: () => fetchJson('/evaluation/results'),
  triggerEvaluationRun: (forceReload = false, seed = 42, sample = 1, log1p = false) =>
    fetchJson(`/evaluation/run?force_reload=${forceReload}&seed=${seed}&sample=${sample}&log1p=${log1p}`, { method: 'POST' }),
  getEvaluationStatus: (jobId) => fetchJson(`/evaluation/status/${jobId}`),
};

