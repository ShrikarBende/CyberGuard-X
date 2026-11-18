import React, { useState, useEffect } from 'react';
import { Sparkles, HelpCircle, Shield, ArrowRight, BarChart2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import { api } from '../services/api';

export default function Explainability() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadIncidents() {
      try {
        const data = await api.getIncidents();
        setIncidents(data);
        if (data.length > 0) {
          setSelectedIncidentId(data[0].incident_id);
          const exp = await api.getExplainability(data[0].incident_id);
          setExplanation(exp);
        }
      } catch (err) {
        console.error('Failed to load explainability data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadIncidents();
  }, []);

  const handleSelectIncident = async (id) => {
    setSelectedIncidentId(id);
    setLoading(true);
    try {
      const exp = await api.getExplainability(id);
      setExplanation(exp);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const chartData = (explanation?.shap_feature_importance || []).map((item) => ({
    feature: item.feature.replace(/_/g, ' '),
    importance: Math.abs(item.value),
    signedValue: item.value,
  }));

  if (!loading && incidents.length === 0) {
    return <div className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-8 text-center text-slate-300">No incidents to explain yet.</div>;
  }

  return (
    <div className="space-y-6">
      {/* Top Selector Bar */}
      <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-purple-400" /> Explainability
          </h3>
          <p className="text-xs text-slate-400">
            SHAP attributions appear when they have been computed and stored.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400">Select Incident:</span>
          <select
            value={selectedIncidentId}
            onChange={(e) => handleSelectIncident(e.target.value)}
            className="bg-[#0D1527] border border-[#1E293B] text-xs font-semibold text-slate-200 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500"
          >
            {incidents.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.title} (Risk: {inc.overall_risk_score.toFixed(0)})
              </option>
            ))}
          </select>
        </div>
      </div>

      {explanation?.available === false ? (
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-8 text-slate-300">
          <p>{explanation.reason}</p>
          {explanation.risk_breakdown && (
            <div className="mt-5 space-y-2">
              <h4 className="text-sm font-bold">Risk score components</h4>
              {Object.entries(explanation.risk_breakdown).map(([name, part]) => (
                <p key={name} className="text-xs text-slate-400">
                  {name.replace(/_/g, ' ')}: value {Number(part.value).toFixed(4)}, weight {Number(part.weight).toFixed(2)}
                </p>
              ))}
            </div>
          )}
        </div>
      ) : !explanation ? (
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-8 text-slate-400">—</div>
      ) : <>
      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* SHAP Feature Attribution Bar Chart (2 cols) */}
        <div className="lg:col-span-2 bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="text-sm font-bold text-slate-200">TreeSHAP Attribution for Predicted Class</h4>
              <p className="text-xs text-slate-500">Positive values raise the selected class output</p>
            </div>
            <span className="text-xs font-mono text-purple-400 font-bold">Signed TreeSHAP values</span>
          </div>

          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={chartData}
                layout="vertical"
                margin={{ top: 10, right: 20, left: 70, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                <XAxis type="number" domain={[0, 'dataMax']} stroke="#64748B" fontSize={11} />
                <YAxis dataKey="feature" type="category" stroke="#94A3B8" fontSize={11} width={130} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0D1527',
                    borderColor: '#1E293B',
                    borderRadius: '8px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                  formatter={(_val, _name, context) => [`${context.payload.signedValue >= 0 ? '+' : ''}${context.payload.signedValue.toFixed(6)}`, 'Signed SHAP']}
                />
                <Bar dataKey="importance" fill="#8B5CF6" radius={[0, 6, 6, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.signedValue >= 0 ? '#EF4444' : '#3B82F6'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Score Components */}
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <h4 className="text-sm font-bold text-slate-200 mb-1">Risk score components</h4>
            <p className="text-xs text-slate-500 mb-4">Configured weights and values used for this incident</p>
            <div className="space-y-3">
              {Object.entries(explanation?.risk_breakdown || {}).map(([name, part]) => (
                <div key={name} className="flex items-center justify-between gap-4 text-xs">
                  <span className="text-slate-400">{name.replace(/_/g, ' ')}</span>
                  <span className="font-mono text-slate-200">{Number(part.value).toFixed(4)} · weight {Number(part.weight).toFixed(2)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#0D1527] border border-[#1E293B] mt-6">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
              Analyst Decision Rationale
            </span>
            <p className="text-xs text-slate-300 mt-1">
              {explanation?.explanation || '—'}
            </p>
          </div>
        </div>
      </div>
      </>}
    </div>
  );
}

