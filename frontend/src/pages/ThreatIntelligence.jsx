import React, { lazy, Suspense, useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Cpu, Layers, HelpCircle, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';

const MitreMatrix = lazy(() => import('../components/MitreMatrix'));

export default function ThreatIntelligence() {
  const [threatData, setThreatData] = useState(null);
  const [novelAlerts, setNovelAlerts] = useState([]);
  const [novelOnly, setNovelOnly] = useState(true);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    async function loadData() {
      try {
        const [data, novel] = await Promise.all([api.getThreats(), api.getAlerts('UNKNOWN_NOVEL', 100)]);
        setThreatData(data);
        setNovelAlerts(novel);
      } catch (err) {
        console.error('Failed to load threat intelligence:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const { summary, known_categories } = threatData || {};

  return (
    <div className="space-y-5">
      <div role="tablist" aria-label="Threat intelligence views" onKeyDown={(event) => {
        if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
        event.preventDefault();
        setActiveTab((current) => current === 'overview' ? 'mitre' : 'overview');
        event.currentTarget.querySelector(`[data-view-tab="${activeTab === 'overview' ? 'mitre' : 'overview'}"]`)?.focus();
      }} className="flex gap-1 border-b border-white/[0.07]">
        <button type="button" id="threat-overview-tab" role="tab" aria-controls="threat-overview-panel" data-view-tab="overview" aria-selected={activeTab === 'overview'} tabIndex={activeTab === 'overview' ? 0 : -1} onClick={() => setActiveTab('overview')} className={`border-b-2 px-3 py-2.5 text-xs font-semibold transition-colors ${activeTab === 'overview' ? 'border-blue-400 text-slate-100' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>Threat intelligence</button>
        <button type="button" id="threat-mitre-tab" role="tab" aria-controls="threat-mitre-panel" data-view-tab="mitre" aria-selected={activeTab === 'mitre'} tabIndex={activeTab === 'mitre' ? 0 : -1} onClick={() => setActiveTab('mitre')} className={`border-b-2 px-3 py-2.5 text-xs font-semibold transition-colors ${activeTab === 'mitre' ? 'border-blue-400 text-slate-100' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>MITRE ATT&amp;CK</button>
      </div>
      {activeTab === 'mitre' ? <div id="threat-mitre-panel" role="tabpanel" aria-labelledby="threat-mitre-tab"><Suspense fallback={<div aria-busy="true" className="space-y-3 rounded-2xl border border-white/[0.07] bg-[#10182E] p-5"><div className="h-4 w-44 animate-pulse rounded bg-white/[0.07]" /><div className="h-24 animate-pulse rounded bg-white/[0.07]" /></div>}><MitreMatrix /></Suspense></div> : loading && !threatData ? <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab" className="h-full flex items-center justify-center text-slate-500">Loading Threat Intelligence Matrix...</div> : <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab" className="space-y-6">
      <section className="rounded-2xl border border-fuchsia-500/40 bg-fuchsia-500/[0.06] p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div><p className="text-[10px] font-bold uppercase tracking-widest text-fuchsia-300">Open-set triage</p><h2 className="mt-1 text-base font-extrabold text-slate-100">Unknown / Novel Threat View</h2><p className="mt-1 text-xs text-slate-400">Review behavior that falls outside known-class confidence or centroid boundaries.</p></div>
          <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={novelOnly} onChange={(event) => setNovelOnly(event.target.checked)} className="accent-fuchsia-500" /> UNKNOWN_NOVEL only</label>
        </div>
        <div className="mt-4 rounded-xl border border-fuchsia-500/30 bg-[#0D1527] p-3 text-sm font-bold text-fuchsia-100">Novel / Unfamiliar Behavior — Requires Analyst Triage</div>
        <div className="mt-3 space-y-2">
          {(novelOnly ? novelAlerts : (threatData?.unknown_candidates || [])).map((item) => {
            const distance = item.centroid_distance ?? item.open_set_distance;
            const novelty = item.novelty_score ?? item.details?.open_set_score;
            return <article key={item.detection_id || item.event_id} className="grid gap-2 rounded-xl border border-[#26344D] bg-[#0D1527] p-3 sm:grid-cols-[1fr_auto] sm:items-center">
              <div><div className="flex flex-wrap items-center gap-2"><span className="text-xs font-bold text-fuchsia-200">{item.verdict || 'UNKNOWN_NOVEL'}</span><span className="font-mono text-[10px] text-slate-500">Event {item.event_id?.slice(-10) || '—'}</span></div><p className="mt-1 text-[10px] text-slate-500">{item.timestamp || item.created_at ? new Date(item.timestamp || item.created_at).toLocaleString() : 'Timestamp unavailable'}</p></div>
              <div className="flex gap-4 text-xs"><span className="text-slate-400">Centroid distance <strong className="ml-1 font-mono text-amber-300">{distance == null ? '—' : Number(distance).toFixed(4)}</strong></span><span className="text-slate-400">Novelty score <strong className="ml-1 font-mono text-fuchsia-300">{novelty == null ? '—' : Number(novelty).toFixed(3)}</strong></span></div>
            </article>;
          })}
          {(novelOnly ? novelAlerts : threatData?.unknown_candidates || []).length === 0 && <p className="py-3 text-xs text-slate-500">No UNKNOWN_NOVEL detections are currently recorded.</p>}
        </div>
      </section>
      {/* Overview Metric Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Total Detections</p>
          <p className="text-2xl font-bold text-slate-100 mt-1">{summary?.total_detections ?? '—'}</p>
        </div>
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Known Attacks (Supervised)</p>
          <p className="text-2xl font-bold text-amber-400 mt-1">{summary?.known_threats_count ?? '—'}</p>
        </div>
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Unknown Candidates</p>
          <p className="text-2xl font-bold text-purple-400 mt-1">{summary?.unknown_candidates_count ?? '—'}</p>
        </div>
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Candidate Rate</p>
          <p className="text-2xl font-bold text-emerald-400 mt-1">{summary?.candidate_rate == null ? '—' : `${(summary.candidate_rate * 100).toFixed(1)}%`}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Known Threat Categories */}
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-200">Classified Known Attack Families</h3>
              <p className="text-xs text-slate-500">CICIDS2017 LightGBM classifier</p>
            </div>
          </div>

          <div className="space-y-3">
            {(known_categories || []).map((cat, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-[#0D1527] border border-[#1E293B] flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold text-slate-200">{cat}</p>
                  <p className="text-[11px] text-slate-500">Model class exceeded its configured logit-margin threshold</p>
                </div>
                <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  CLASSIFIED
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Unknown Threats Queue (Open-Set Detection) */}
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-200">Unconfirmed Candidate Queue</h3>
              <p className="text-xs text-slate-500">Flows rejected by the known-validation score threshold; candidates need analyst review</p>
            </div>
          </div>

          <div className="space-y-3">
            {(threatData?.unknown_candidates || []).slice(0, 4).map((th, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-[#0D1527] border border-purple-500/20 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-purple-300">Unconfirmed candidate</span>
                    <span className="text-[10px] font-mono text-slate-500">#{th.event_id?.slice(-6)}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Latent Distance: <span className="text-purple-400 font-mono font-bold">{th.open_set_distance?.toFixed(2) ?? '—'}</span>
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono font-bold text-rose-400">
                    Recon Err: {th.reconstruction_error?.toFixed(3) ?? '—'}
                  </span>
                  <p className="text-[10px] text-slate-500">{new Date(th.timestamp).toLocaleTimeString()}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
      </div>}
    </div>
  );
}

