import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Users,
  Server,
  Network,
  AlertTriangle,
  Activity,
  Layers,
  ArrowUpRight,
  TrendingUp,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import { api } from '../services/api';

const COLORS = ['#3B82F6', '#EF4444', '#F59E0B', '#10B981', '#A855F7'];

export default function Overview({ onSelectIncident }) {
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [dashStats, alerts] = await Promise.all([
          api.getDashboardStats(),
          api.getAlerts('', 8),
        ]);
        setStats(dashStats);
        setRecentAlerts(alerts);
      } catch (err) {
        console.error('Failed to load overview data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="h-full flex items-center justify-center text-slate-500">
        <Activity className="w-6 h-6 animate-spin text-blue-500 mr-2" />
        <span>Loading Executive Overview...</span>
      </div>
    );
  }

  const kpis = [
    {
      label: 'Total Events Analyzed',
      value: stats?.total_events ?? '—',
      icon: Activity,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10 border-blue-500/20',
    },
    {
      label: 'Known Threats Detected',
      value: stats?.known_threats ?? '—',
      icon: ShieldAlert,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10 border-amber-500/20',
    },
    {
      label: 'Unknown Candidates',
      value: stats?.unknown_candidates ?? '—',
      icon: AlertTriangle,
      color: 'text-purple-400',
      bg: 'bg-purple-500/10 border-purple-500/20',
      tag: 'Open-Set Gate',
    },
    {
      label: 'Critical Incidents',
      value: stats?.critical_incidents ?? '—',
      icon: ShieldAlert,
      color: 'text-rose-400',
      bg: 'bg-rose-500/10 border-rose-500/20',
    },
  ];

  return (
    <div className="space-y-6">
      {stats?.total_detections === 0 && <div role="status" className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-4 text-sm text-slate-300">No detections yet. Ingest an event and run it through the detector to populate this view.</div>}
      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map((kpi, idx) => {
          const Icon = kpi.icon;
          return (
            <div
              key={idx}
              className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-5 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  {kpi.label}
                </span>
                <div className={`p-2 rounded-xl border ${kpi.bg}`}>
                  <Icon className={`w-4 h-4 ${kpi.color}`} />
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-extrabold text-slate-100">{kpi.value}</span>
                {kpi.tag && (
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    {kpi.tag}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Trend Chart (2 cols) */}
        <div className="lg:col-span-2 bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-sm font-bold text-slate-200">Enterprise Risk Score Trend (Last 60 Min)</h3>
              <p className="text-xs text-slate-500">Stored incident risk scores over time</p>
            </div>
            <span className="flex items-center gap-1 text-xs text-emerald-400 font-mono">
              <TrendingUp className="w-3.5 h-3.5" /> API data
            </span>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats?.risk_trend || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0D1527',
                    borderColor: '#1E293B',
                    borderRadius: '8px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="risk"
                  stroke="#EF4444"
                  strokeWidth={2.5}
                  dot={{ r: 3, fill: '#EF4444' }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution Donut (1 col) */}
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-200 mb-1">Threat Category Breakdown</h3>
            <p className="text-xs text-slate-500 mb-4">MITRE ATT&CK & Open-Set Classification</p>
          </div>

          <div className="h-48 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={stats?.threat_distribution || []}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {(stats?.threat_distribution || []).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0D1527',
                    borderColor: '#1E293B',
                    borderRadius: '8px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="space-y-1.5 mt-2">
            {(stats?.threat_distribution || []).slice(0, 4).map((item, idx) => (
              <div key={idx} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: COLORS[idx % COLORS.length] }}
                  ></div>
                  <span className="text-slate-300">{item.name}</span>
                </div>
                <span className="font-mono text-slate-400">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Layer-Wise Detection Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400">User / Identity Layer</p>
            <p className="text-lg font-bold text-slate-100">
              {stats?.layer_detection_stats?.user_identity ?? '—'} Anomaly Flags
            </p>
            <span className="text-[11px] text-slate-500">Impossible travel, auth bursts, off-hours</span>
          </div>
        </div>

        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400">Endpoint / Device (Autoencoder + iForest)</p>
            <p className="text-lg font-bold text-slate-100">
              {stats?.layer_detection_stats?.endpoint_device ?? '—'} Process Anomalies
            </p>
            <span className="text-[11px] text-slate-500">LOLBAS, memory inject, high entropy</span>
          </div>
        </div>

        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400">Network Layer (Flows)</p>
            <p className="text-lg font-bold text-slate-100">
              {stats?.layer_detection_stats?.network_traffic ?? '—'} Flow Detections
            </p>
            <span className="text-[11px] text-slate-500">Lateral SMB, covert C2, port scans</span>
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed Table */}
      <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-200">Recent Detection Results</h3>
            <p className="text-xs text-slate-500">Real-time open-set inference scores and attack probabilities</p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-slate-400 font-semibold uppercase tracking-wider">
                <th className="pb-3">Verdict</th>
                <th className="pb-3">Threat Category</th>
                <th className="pb-3">Layer</th>
                <th className="pb-3">Score</th>
                <th className="pb-3">Attack Probability</th>
                <th className="pb-3">Open-Set Distance</th>
                <th className="pb-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60 text-slate-300">
              {recentAlerts.map((alert) => {
                const isCandidate = alert.verdict === 'UNKNOWN_CANDIDATE';
                return (
                  <tr key={alert.detection_id} className="hover:bg-[#131D38]/50 transition-colors">
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                          isCandidate
                            ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                            : alert.verdict === 'KNOWN_THREAT'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        }`}
                      >
                        {alert.verdict.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="py-3 font-medium text-slate-200">{alert.predicted_class}</td>
                    <td className="py-3 uppercase text-slate-400 font-mono">{alert.layer}</td>
                    <td className="py-3 font-mono">{alert.score == null ? '—' : alert.score.toFixed(2)}</td>
                    <td className="py-3 font-mono">{alert.attack_probability == null ? '—' : `${(alert.attack_probability * 100).toFixed(1)}%`}</td>
                    <td className="py-3 font-mono">
                      <span className="text-slate-400">
                        {alert.open_set_distance == null ? '—' : alert.open_set_distance.toFixed(2)}
                      </span>
                    </td>
                    <td className="py-3 text-slate-500 font-mono">
                      {new Date(alert.created_at).toLocaleTimeString()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

