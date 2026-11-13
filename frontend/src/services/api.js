/**
 * Enterprise CyberGuard X - API Client Service
 */

const API_BASE = '/api';

async function fetchJson(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  };

  try {
    const res = await fetch(url, config);
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.detail || `HTTP Error ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    console.error(`API call failed [${url}]:`, err);
    throw err;
  }
}

export const api = {
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

  // 6. RAG Chat Assistant
  ragChat: (query, incidentId = null) =>
    fetchJson('/rag/chat', {
      method: 'POST',
      body: JSON.stringify({ query, incident_id: incidentId }),
    }),

  // 7. Models & CICIDS2017
  getCicidsStatus: () => fetchJson('/datasets/cicids'),
  trainCicids: (sampleSize = 3000) =>
    fetchJson(`/models/train-cicids?sample_size=${sampleSize}`, {
      method: 'POST',
    }),
  trainModels: (modelName = 'all', nSamples = 1000) =>
    fetchJson('/models/train', {
      method: 'POST',
      body: JSON.stringify({ model_name: modelName, n_samples: nSamples }),
    }),
  getModelsStatus: () => fetchJson('/models/status'),

  // 8. Ingestion & Upload
  uploadLogs: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
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

