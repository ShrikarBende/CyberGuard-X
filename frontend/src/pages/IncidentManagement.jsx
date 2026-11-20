import React, { useState, useEffect } from 'react';
import {
  FileWarning,
  CheckCircle2,
  Clock,
  User,
  Server,
  Layers,
  ChevronRight,
  Plus,
  Send,
  X,
  ShieldAlert,
  Activity,
} from 'lucide-react';
import { api } from '../services/api';
import RiskFusion from '../components/RiskFusion';

export default function IncidentManagement({ onSelectIncidentForAssistant, role = 'viewer' }) {
  const canInvestigate = role === 'analyst' || role === 'admin';
  const isAdmin = role === 'admin';
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(true);
  const [correlationRunning, setCorrelationRunning] = useState(false);
  const [correlationMessage, setCorrelationMessage] = useState('');
  const [correlationAlerts, setCorrelationAlerts] = useState([]);
  const [actionMessage, setActionMessage] = useState('');
  const reviewQueue = incidents.filter((incident) => incident.status === 'NEEDS_REVIEW');

  const fetchIncidents = async () => {
    try {
      const data = await api.getIncidents();
      setIncidents(data);
      if (data.length > 0 && !selectedIncident) {
        setSelectedIncident(data[0]);
      }
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleRunCorrelation = async () => {
    setCorrelationRunning(true);
    setCorrelationMessage('');
    try {
      const result = await api.runCorrelation(60);
      setCorrelationAlerts(result.alerts || []);
      setCorrelationMessage(`Checked ${result.alerts?.length || 0} rule indicators; created or matched ${result.incidents?.length || 0} correlated incidents.`);
      await fetchIncidents();
    } catch (err) {
      setCorrelationMessage(err.message || 'Correlation run failed.');
    } finally {
      setCorrelationRunning(false);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-400">Loading incidents…</div>;
  }

  const handleStatusChange = async (incidentId, newStatus) => {
    try {
      await api.updateIncidentStatus(incidentId, newStatus);
      fetchIncidents();
      if (selectedIncident?.incident_id === incidentId) {
        setSelectedIncident((prev) => ({ ...prev, status: newStatus }));
      }
      setActionMessage('Incident status updated.');
    } catch (err) {
      setActionMessage(err.message || 'Failed to update status.');
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !selectedIncident) return;
    try {
      const created = await api.addIncidentNote(selectedIncident.incident_id, newNote);
      setSelectedIncident((prev) => ({
        ...prev,
        notes: [created, ...(prev.notes || [])],
      }));
      setNewNote('');
      setActionMessage('Note added.');
    } catch (err) {
      setActionMessage(err.message || 'Failed to add note.');
    }
  };

  return (
    <div className="space-y-4">
      {actionMessage && <p role="status" className="rounded-xl border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs text-blue-200">{actionMessage}</p>}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[#1E293B] bg-[#10182E] p-4">
        <div>
          <h3 className="text-sm font-bold text-slate-200">Rule-based cross-layer correlation</h3>
          <p className="text-xs text-slate-500 mt-1">Signals are rule indicators; they are not ML predictions.</p>
          {correlationMessage && <p className="text-xs text-blue-200 mt-2">{correlationMessage}</p>}
        </div>
        {isAdmin && <button onClick={handleRunCorrelation} disabled={correlationRunning}
          className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-2">
          <Activity className="w-4 h-4" /> {correlationRunning ? 'Correlating…' : 'Run correlation (60 min)'}
        </button>}
      </div>

      <section className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-amber-200">Model review queue</h3>
          <span className="text-xs font-mono text-amber-300">{reviewQueue.length}</span>
        </div>
        {reviewQueue.length === 0 ? (
          <p className="text-xs text-slate-500">No unknown candidates need review.</p>
        ) : (
          <div className="space-y-2">
            {reviewQueue.map((item) => (
              <button key={item.incident_id} onClick={() => setSelectedIncident(item)} className="w-full flex items-center justify-between rounded-xl bg-[#0D1527] border border-amber-500/20 p-3 text-left">
                <span className="text-xs text-slate-200">{item.title}<span className="block text-[10px] text-slate-500 mt-1">{item.description}</span></span>
                <span className="text-xs font-mono text-amber-300">{item.flow_count || 1} flows</span>
              </button>
            ))}
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-220px)]">
      {/* Incidents List (Left col) */}
      <div className="lg:col-span-1 bg-[#10182E] border border-[#1E293B] rounded-2xl p-5 flex flex-col overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-slate-200">Correlated incidents</h3>
          <span className="text-xs font-mono text-slate-400">{incidents.length} Active</span>
        </div>

        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {incidents.map((inc) => {
            const isSelected = selectedIncident?.incident_id === inc.incident_id;
            const isCritical = inc.severity === 'CRITICAL';
              const isRuleCorrelated = inc.threat_classification === 'RULE_CORRELATED_SUSPICIOUS_ACTIVITY';
              const isDemo = (inc.evidence?.indicators || []).some((indicator) => indicator.dataset === 'synthetic_demo' || indicator.is_demo);
            return (
              <button
                type="button"
                key={inc.incident_id}
                aria-pressed={isSelected}
                onClick={() => setSelectedIncident(inc)}
                className={`w-full text-left p-3.5 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-blue-600/10 border-blue-500 shadow-md'
                    : 'bg-[#0D1527] border-[#1E293B] hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                      isCritical
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                    }`}
                  >
                    {inc.severity}
                  </span>
                  <span className="text-xs font-bold font-mono text-rose-400">
                    Risk: {inc.overall_risk_score.toFixed(1)}
                  </span>
                </div>

                <p className="text-xs font-bold text-slate-200 line-clamp-1">{inc.title}</p>
                {isRuleCorrelated && <div className="mt-2 flex flex-wrap gap-1.5">
                  {isDemo && <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[9px] font-bold tracking-wide text-amber-200">DEMO</span>}
                  <span className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[9px] font-bold tracking-wide text-cyan-200">RULE-CORRELATED</span>
                </div>}
                <p className="text-[10px] text-slate-500 mt-1">{inc.flow_count || 1} flows</p>
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                  <span>{inc.user_id || 'host_sys'}</span>
                  <span>{inc.device_id || 'unknown_host'}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Incident Detail (Right 2 cols) */}
      <div className="lg:col-span-2 bg-[#10182E] border border-[#1E293B] rounded-2xl p-6 flex flex-col overflow-y-auto">
        {selectedIncident ? (
          <div className="space-y-6">
            {/* Header with Title & Status Dropdown */}
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#1E293B] pb-5">
              <div>
                <span className="text-xs font-mono text-blue-400">
                  INCIDENT #{selectedIncident.incident_id.slice(-8).toUpperCase()}
                </span>
                <h2 className="text-lg font-extrabold text-slate-100 mt-0.5">
                  {selectedIncident.title}
                </h2>
                <p className="text-xs text-slate-400 mt-1">{selectedIncident.description}</p>
              </div>

              <div className="flex items-center gap-3">
                {canInvestigate && <select
                  value={selectedIncident.status}
                  onChange={(e) => handleStatusChange(selectedIncident.incident_id, e.target.value)}
                  className="bg-[#0D1527] border border-[#1E293B] text-xs font-semibold text-slate-200 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500"
                >
                  {selectedIncident.status === 'open' && <option value="open">Status: open</option>}
                  <option value="OPEN">Status: OPEN</option>
                  <option value="NEEDS_REVIEW">Status: NEEDS_REVIEW</option>
                  <option value="INVESTIGATING">Status: INVESTIGATING</option>
                  <option value="CONTAINED">Status: CONTAINED</option>
                  <option value="RESOLVED">Status: RESOLVED</option>
                  <option value="FALSE_POSITIVE">Status: FALSE_POSITIVE</option>
                </select>}

                {onSelectIncidentForAssistant && (
                  <button
                    onClick={() => onSelectIncidentForAssistant(selectedIncident.incident_id)}
                    className="px-3.5 py-2 rounded-xl bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold transition-all shadow-md shadow-purple-600/30 flex items-center gap-1.5"
                  >
                    Ask AI Assistant
                  </button>
                )}
              </div>
            </div>

            {selectedIncident.threat_classification === 'RULE_CORRELATED_SUSPICIOUS_ACTIVITY' && (() => {
              const isDemo = (selectedIncident.evidence?.indicators || []).some((indicator) => indicator.dataset === 'synthetic_demo' || indicator.is_demo);
              return <div className="flex flex-wrap gap-2" aria-label="Incident provenance badges">
                {isDemo && <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[10px] font-bold tracking-wide text-amber-200">DEMO</span>}
                <span className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[10px] font-bold tracking-wide text-cyan-200">RULE-CORRELATED</span>
              </div>;
            })()}

            {(() => {
              const fusion = selectedIncident.evidence?.risk_fusion || selectedIncident.risk_score_detail?.risk_breakdown?.fusion || {};
              return <RiskFusion explanation={{
                severity: fusion.severity || selectedIncident.severity,
                calibrated_risk_score: fusion.probability,
                overall_risk_score: selectedIncident.overall_risk_score,
                per_layer_contributions: fusion.contributions || {},
              }} />;
            })()}
            {String(selectedIncident.threat_classification || '').includes('UNKNOWN') && <div className="rounded-xl border border-fuchsia-500/40 bg-fuchsia-500/10 p-3 text-xs font-semibold text-fuchsia-100">Novel / Unfamiliar Behavior — Requires Analyst Triage. This open-set candidate is not a confirmed attack.</div>}

            {/* Target Entities Row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-[#0D1527] border border-[#1E293B] rounded-xl p-3">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Compromised User</span>
                <p className="text-xs font-bold text-slate-200 mt-0.5">{selectedIncident.user_id || 'N/A'}</p>
              </div>
              <div className="bg-[#0D1527] border border-[#1E293B] rounded-xl p-3">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Target Device</span>
                <p className="text-xs font-bold text-slate-200 mt-0.5">{selectedIncident.device_id || 'N/A'}</p>
              </div>
              <div className="bg-[#0D1527] border border-[#1E293B] rounded-xl p-3">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Classification</span>
                <p className="text-xs font-bold text-purple-400 mt-0.5">{selectedIncident.threat_classification}</p>
              </div>
              <div className="bg-[#0D1527] border border-[#1E293B] rounded-xl p-3">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">First Detected</span>
                <p className="text-xs font-mono text-slate-200 mt-0.5">
                  {new Date(selectedIncident.first_detected_at).toLocaleTimeString()}
                </p>
              </div>
              <div className="bg-[#0D1527] border border-[#1E293B] rounded-xl p-3">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Flow Count</span>
                <p className="text-xs font-bold text-slate-200 mt-0.5">{selectedIncident.flow_count || 1}</p>
              </div>
            </div>

            {selectedIncident.evidence?.score_summary && (
              <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Model score summary</h4>
                <p className="text-xs text-slate-300">Score mean {Number(selectedIncident.evidence.score_summary.mean).toFixed(4)} · min {Number(selectedIncident.evidence.score_summary.min).toFixed(4)} · max {Number(selectedIncident.evidence.score_summary.max).toFixed(4)} · {selectedIncident.evidence.score_summary.count} scored flows</p>
                {selectedIncident.evidence.review_text && <p className="text-xs text-amber-200 mt-2">{selectedIncident.evidence.review_text}</p>}
                <pre className="mt-2 whitespace-pre-wrap text-[10px] text-slate-400">{JSON.stringify(selectedIncident.evidence.risk_breakdown || {}, null, 2)}</pre>
              </div>
            )}

            {selectedIncident.threat_classification === 'RULE_CORRELATED_SUSPICIOUS_ACTIVITY' && (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 space-y-4">
                <p className="text-xs font-semibold text-amber-200">Correlated suspicious activity; not a confirmed attack.</p>
                <div>
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Attack sequence</h4>
                  <ol className="space-y-2 border-l border-blue-500/40 ml-2">
                    {(selectedIncident.attack_sequence || []).map((stage, index) => (
                      <li key={`${stage.indicator}-${index}`} className="pl-4 relative">
                        <span className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-blue-400" />
                        <div className="text-xs text-slate-200 font-semibold">{index + 1}. {stage.indicator || stage.stage}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{new Date(stage.timestamp).toLocaleString()} · {stage.layer} · events: {(stage.event_ids || []).join(', ')}</div>
                        <pre className="mt-1 whitespace-pre-wrap break-all text-[10px] text-slate-400">{JSON.stringify(stage.evidence || {}, null, 2)}</pre>
                      </li>
                    ))}
                  </ol>
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-1">Risk component breakdown</h4>
                  <pre className="whitespace-pre-wrap text-[10px] text-slate-400">{JSON.stringify(selectedIncident.evidence?.risk_breakdown || selectedIncident.risk_score_detail?.risk_breakdown || {}, null, 2)}</pre>
                </div>
              </div>
            )}

            {/* MITRE ATT&CK Mapping */}
            <div>
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                Evidence-Gated MITRE ATT&CK Techniques
              </h4>
              <div className="flex flex-wrap gap-2">
                {(selectedIncident.mitre_mappings || []).map((m, idx) => (
                  <div
                    key={idx}
                    className="px-3 py-1.5 rounded-xl bg-[#0D1527] border border-blue-500/30 text-xs flex items-center gap-2"
                  >
                    <span className="font-mono text-blue-400 font-bold">{m.technique_id}</span>
                    <span className="text-slate-300">{m.technique_name}</span>
                    <span className="text-[10px] text-slate-500">({m.tactic})</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Investigation Notes & Audit Log */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Analyst Investigation Notes
              </h4>

              {/* Add Note Form */}
              {canInvestigate && <form onSubmit={handleAddNote} className="flex gap-2">
                <input
                  type="text"
                  placeholder="Add triage note, containment action, or forensic finding..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  className="flex-1 bg-[#0D1527] border border-[#1E293B] text-slate-200 text-xs rounded-xl px-3 py-2.5 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="submit"
                  className="px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold transition-all flex items-center gap-1.5"
                >
                  <Send className="w-3.5 h-3.5" /> Save Note
                </button>
              </form>}

              {/* Notes List */}
              <div className="space-y-2">
                {(selectedIncident.notes || []).map((note, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-[#0D1527] border border-[#1E293B] text-xs">
                    <div className="flex items-center justify-between text-slate-500 mb-1">
                      <span className="font-bold text-slate-300">{note.author}</span>
                      <span className="font-mono text-[10px]">{new Date(note.created_at).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-slate-200">{note.content}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center text-slate-400 px-8">
            <ShieldAlert className="w-8 h-8 text-slate-600 mb-3" />
            <p className="text-sm font-semibold">No correlated incidents yet.</p>
            <p className="text-xs mt-2">Load synthetic demo events from Data Management, then run correlation here. Matching rules produce alerts; an incident requires three indicator types across two layers.</p>
          </div>
        )}
      </div>
      </div>

      {correlationAlerts.length > 0 && (
        <div className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-5">
          <h3 className="text-sm font-bold text-slate-200 mb-3">Rule indicator alerts</h3>
          <div className="space-y-2">
            {correlationAlerts.map((alert, index) => (
              <div key={`${alert.name}-${index}`} className="rounded-xl border border-[#1E293B] bg-[#0D1527] p-3">
                <div className="flex flex-wrap justify-between gap-2 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-blue-300">{alert.name.replaceAll('_', ' ')}</span>
                    {alert.is_demo && <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[9px] font-bold text-amber-200">DEMO</span>}
                    <span className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[9px] font-bold text-cyan-200">RULE-CORRELATED</span>
                  </div>
                  <span className="font-mono text-slate-500">{new Date(alert.timestamp).toLocaleString()} · {alert.layer}</span>
                </div>
                {alert.scenario && <p className="text-[10px] text-amber-200 mt-1">Demo scenario: {alert.scenario.replaceAll('_', ' ')}</p>}
                <p className="text-[11px] text-slate-300 mt-1">{alert.rule}</p>
                <p className="text-[10px] text-slate-500 mt-1">Evidence event IDs: {(alert.event_ids || []).join(', ')}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

