import React, { useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Cpu, Layers, HelpCircle, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';

export default function ThreatIntelligence() {
  const [threatData, setThreatData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const data = await api.getThreats();
        setThreatData(data);
      } catch (err) {
        console.error('Failed to load threat intelligence:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading && !threatData) {
    return (
      <div className="h-full flex items-center justify-center text-slate-500">
        Loading Threat Intelligence Matrix...
      </div>
    );
  }

  const { summary, known_categories, unknown_novel_threats } = threatData || {};

  return (
    <div className="space-y-6">
      {/* Overview Metric Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Total Flagged Threats</p>
          <p className="text-2xl font-bold text-slate-100 mt-1">{summary?.total_detected_threats || 0}</p>
        </div>
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Known Attacks (Supervised)</p>
          <p className="text-2xl font-bold text-amber-400 mt-1">{summary?.known_threats_count || 0}</p>
        </div>
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Unknown / Novel (Open-Set)</p>
          <p className="text-2xl font-bold text-purple-400 mt-1">{summary?.unknown_threats_count || 0}</p>
        </div>
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5">
          <p className="text-xs text-slate-400 font-semibold uppercase">Novelty Rejection Rate</p>
          <p className="text-2xl font-bold text-emerald-400 mt-1">{((summary?.novelty_rate || 0) * 100).toFixed(1)}%</p>
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
              <p className="text-xs text-slate-500">Supervised XGBoost multi-class classifier</p>
            </div>
          </div>

          <div className="space-y-3">
            {(known_categories || ['Brute Force', 'Port Scan', 'LOLBAS Execution', 'Lateral Movement']).map((cat, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-[#0D1527] border border-[#1E293B] flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold text-slate-200">{cat}</p>
                  <p className="text-[11px] text-slate-500">Evidence predicate matched against MITRE technique</p>
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
              <h3 className="text-sm font-bold text-slate-200">Open-Set Novel Threats Queue</h3>
              <p className="text-xs text-slate-500">Mahalanobis distance & Denoising Autoencoder residual</p>
            </div>
          </div>

          <div className="space-y-3">
            {(unknown_novel_threats || []).slice(0, 4).map((th, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-[#0D1527] border border-purple-500/20 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-purple-300">Novel / Zero-Day Pattern</span>
                    <span className="text-[10px] font-mono text-slate-500">#{th.event_id?.slice(-6)}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Latent Distance: <span className="text-purple-400 font-mono font-bold">{th.open_set_distance?.toFixed(2)}</span> (Threshold: 4.20)
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono font-bold text-rose-400">
                    Recon Err: {th.reconstruction_error?.toFixed(3)}
                  </span>
                  <p className="text-[10px] text-slate-500">{new Date(th.timestamp).toLocaleTimeString()}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

