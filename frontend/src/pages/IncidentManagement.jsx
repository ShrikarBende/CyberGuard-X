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
} from 'lucide-react';
import { api } from '../services/api';

export default function IncidentManagement({ onSelectIncidentForAssistant }) {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(true);

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

  const handleStatusChange = async (incidentId, newStatus) => {
    try {
      await api.updateIncidentStatus(incidentId, newStatus);
      fetchIncidents();
      if (selectedIncident?.incident_id === incidentId) {
        setSelectedIncident((prev) => ({ ...prev, status: newStatus }));
      }
    } catch (err) {
      alert('Failed to update status');
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
    } catch (err) {
      alert('Failed to add note');
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-140px)]">
      {/* Incidents List (Left col) */}
      <div className="lg:col-span-1 bg-[#10182E] border border-[#1E293B] rounded-2xl p-5 flex flex-col overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-slate-200">Correlated Attack Incidents</h3>
          <span className="text-xs font-mono text-slate-400">{incidents.length} Active</span>
        </div>

        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {incidents.map((inc) => {
            const isSelected = selectedIncident?.incident_id === inc.incident_id;
            const isCritical = inc.severity === 'CRITICAL';
            return (
              <div
                key={inc.incident_id}
                onClick={() => setSelectedIncident(inc)}
                className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
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
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                  <span>{inc.user_id || 'host_sys'}</span>
                  <span>{inc.device_id || 'unknown_host'}</span>
                </div>
              </div>
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
                <select
                  value={selectedIncident.status}
                  onChange={(e) => handleStatusChange(selectedIncident.incident_id, e.target.value)}
                  className="bg-[#0D1527] border border-[#1E293B] text-xs font-semibold text-slate-200 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500"
                >
                  <option value="OPEN">Status: OPEN</option>
                  <option value="INVESTIGATING">Status: INVESTIGATING</option>
                  <option value="CONTAINED">Status: CONTAINED</option>
                  <option value="RESOLVED">Status: RESOLVED</option>
                  <option value="FALSE_POSITIVE">Status: FALSE_POSITIVE</option>
                </select>

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
            </div>

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
              <form onSubmit={handleAddNote} className="flex gap-2">
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
              </form>

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
          <div className="h-full flex items-center justify-center text-slate-500">
            Select an incident to view details
          </div>
        )}
      </div>
    </div>
  );
}

