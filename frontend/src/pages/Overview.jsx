import React, { useEffect, useId, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Clock3,
  Network,
  Server,
  ShieldAlert,
  Users,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Line,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { api } from '../services/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import EmptyState from '../components/ui/EmptyState';
import Skeleton from '../components/ui/Skeleton';
import { createMotionScope, motion, prefersReducedMotion } from '../lib/motion';
import { chartTheme } from '../charts/chartTheme';

const KPI_TONES = [
  { tone: 'low', accent: 'var(--soc-low)' },
  { tone: 'medium', accent: 'var(--soc-medium)' },
  { tone: 'novel', accent: 'var(--soc-novel)' },
  { tone: 'critical', accent: 'var(--soc-critical)' },
];

function CountUpValue({ value, className = '' }) {
  const valueRef = useRef(null);
  const animated = useRef(false);

  useGSAP(() => {
    if (!valueRef.current) return;
    if (animated.current) {
      valueRef.current.textContent = String(value);
      return;
    }

    const target = Number(value);
    if (!Number.isFinite(target)) {
      valueRef.current.textContent = String(value);
      return;
    }

    animated.current = true;
    let firstMotionPass = true;
    return createMotionScope(valueRef.current, (reduced) => {
      if (!firstMotionPass) {
        valueRef.current.textContent = String(value);
        return;
      }
      firstMotionPass = false;
      if (reduced) {
        valueRef.current.textContent = String(value);
        return;
      }

      const counter = { value: 0 };
      gsap.to(counter, {
        value: target,
        duration: motion.duration.entrance,
        ease: motion.easeSoft,
        onUpdate: () => {
          if (valueRef.current) valueRef.current.textContent = Math.round(counter.value).toLocaleString();
        },
        onComplete: () => {
          if (valueRef.current) valueRef.current.textContent = String(value);
        },
      });
    });
  }, { scope: valueRef, dependencies: [value], revertOnUpdate: false });

  return <span ref={valueRef} className={className}>{String(value)}</span>;
}

function LoadingOverview() {
  return (
    <div className="mx-auto w-full max-w-[1600px] space-y-6" role="status" aria-label="Loading Executive Overview">
      <span className="sr-only">Loading Executive Overview...</span>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Card key={index} className="min-h-36 space-y-5">
            <Skeleton className="h-3 w-32" />
            <Skeleton className="h-9 w-24" />
          </Card>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="h-[22rem] lg:col-span-2"><Skeleton className="h-full w-full" /></Card>
        <Card className="h-[22rem]"><Skeleton className="h-full w-full" /></Card>
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {Array.from({ length: 3 }, (_, index) => <Card key={index} className="h-28"><Skeleton className="h-full w-full" /></Card>)}
      </div>
      <Card className="h-64"><Skeleton className="h-full w-full" /></Card>
    </div>
  );
}

function categoryColor(name) {
  const normalized = String(name || '').toLowerCase();
  if (normalized.includes('unknown') || normalized.includes('novel')) return 'var(--soc-novel)';
  if (normalized.includes('benign') || normalized.includes('normal')) return 'var(--soc-normal)';
  if (normalized.includes('critical')) return 'var(--soc-critical)';
  if (normalized.includes('high')) return 'var(--soc-high)';
  if (normalized.includes('medium')) return 'var(--soc-medium)';
  if (normalized.includes('low')) return 'var(--soc-low)';
  return 'var(--soc-low)';
}

function verdictTone(verdict) {
  const normalized = String(verdict || '').toUpperCase();
  if (normalized.includes('UNKNOWN') || normalized.includes('NOVEL')) return 'novel';
  if (normalized.includes('CRITICAL')) return 'critical';
  if (normalized.includes('HIGH')) return 'high';
  if (normalized.includes('MEDIUM')) return 'medium';
  if (normalized.includes('LOW')) return 'low';
  if (normalized.includes('BENIGN') || normalized.includes('NORMAL')) return 'normal';
  if (normalized === 'KNOWN_THREAT') return 'critical';
  return 'neutral';
}

function DetectionCell({ children, detectionId, flash }) {
  return (
    <td className="relative whitespace-nowrap px-4 py-3">
      {flash && <span aria-hidden="true" data-row-flash-id={detectionId} className="pointer-events-none absolute inset-0 bg-blue-400/10 opacity-0" />}
      <span className="relative z-[1]">{children}</span>
    </td>
  );
}

function OverviewTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-36 rounded-xl border border-white/10 bg-slate-950/95 p-3 shadow-2xl backdrop-blur-xl">
      {label != null && <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">{label}</p>}
      <div className="space-y-1.5">
        {payload.map((item, index) => {
          const formatted = formatter ? formatter(item.value, item.name, item) : [item.value, item.name];
          return (
            <div key={`${item.dataKey || item.name}-${index}`} className="flex items-center justify-between gap-5 text-[11px]">
              <span className="flex items-center gap-2 text-slate-300"><i aria-hidden="true" className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color || item.fill }} />{formatted[1] || item.name}</span>
              <span className="soc-mono font-medium text-slate-100">{formatted[0]}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function Overview({ onSelectIncident }) {
  const root = useRef(null);
  const previousAlertIds = useRef(null);
  const flashResetTimer = useRef(null);
  const chartId = useId().replace(/:/g, '');
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [flashAlertIds, setFlashAlertIds] = useState(() => new Set());
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [activeSlice, setActiveSlice] = useState(null);

  useGSAP(() => createMotionScope(root.current, (reduced) => {
    gsap.fromTo('.overview-entrance',
      { autoAlpha: 0, y: reduced ? 0 : 12 },
      {
        autoAlpha: 1,
        y: 0,
        duration: reduced ? 0.18 : 0.48,
        stagger: reduced ? 0 : 0.055,
        ease: motion.ease,
        clearProps: 'transform,visibility',
      },
    );
  }), { scope: root, dependencies: [loading], revertOnUpdate: true });

  useGSAP(() => {
    if (!flashAlertIds.size) return undefined;
    return createMotionScope(root.current, (reduced) => {
      const overlays = Array.from(root.current.querySelectorAll('[data-row-flash-id]'))
        .filter((node) => flashAlertIds.has(node.dataset.rowFlashId));
      if (overlays.length) {
        gsap.fromTo(overlays, { opacity: 0.85 }, {
          opacity: 0,
          duration: reduced ? 0.18 : 0.95,
          ease: 'power2.out',
          overwrite: true,
        });
      }
    });
  }, { scope: root, dependencies: [flashAlertIds], revertOnUpdate: true });

  useEffect(() => {
    async function loadData() {
      try {
        const [dashStats, alerts] = await Promise.all([
          api.getDashboardStats(),
          api.getAlerts('', 8),
        ]);
        const nextIds = new Set(alerts.map((alert) => alert.detection_id).filter(Boolean));
        if (previousAlertIds.current) {
          const newlyAdded = Array.from(nextIds).filter((id) => !previousAlertIds.current.has(id));
          if (newlyAdded.length) {
            setFlashAlertIds(new Set(newlyAdded));
            window.clearTimeout(flashResetTimer.current);
            flashResetTimer.current = window.setTimeout(() => setFlashAlertIds(new Set()), 1100);
          }
        }
        previousAlertIds.current = nextIds;
        setStats(dashStats);
        setRecentAlerts(alerts);
        setLoadError(false);
      } catch (err) {
        console.error('Failed to load overview data:', err);
        setLoadError(true);
      } finally {
        setLoading(false);
      }
    }
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => {
      clearInterval(interval);
      window.clearTimeout(flashResetTimer.current);
    };
  }, []);

  if (loading && !stats) return <LoadingOverview />;

  const kpis = [
    { label: 'Total Events Analyzed', value: stats?.total_events ?? '—', icon: Activity },
    { label: 'Known Threats Detected', value: stats?.known_threats ?? '—', icon: ShieldAlert },
    { label: 'Unknown Candidates', value: stats?.unknown_candidates ?? '—', icon: AlertTriangle, tag: 'Open-Set Gate' },
    { label: 'Critical Incidents', value: stats?.critical_incidents ?? '—', icon: ShieldAlert },
  ];
  const riskTrend = stats?.risk_trend || [];
  const threatDistribution = stats?.threat_distribution || [];
  const threatTotal = threatDistribution.reduce((total, item) => total + (Number(item.value) || 0), 0);
  const layers = [
    {
      title: 'User / Identity Layer',
      value: stats?.layer_detection_stats?.user_identity ?? '—',
      suffix: 'Anomaly Flags',
      detail: 'Impossible travel, auth bursts, off-hours',
      icon: Users,
      tone: 'low',
    },
    {
      title: 'Endpoint / Device (Autoencoder + iForest)',
      value: stats?.layer_detection_stats?.endpoint_device ?? '—',
      suffix: 'Process Anomalies',
      detail: 'LOLBAS, memory inject, high entropy',
      icon: Server,
      tone: 'novel',
    },
    {
      title: 'Network Layer (Flows)',
      value: stats?.layer_detection_stats?.network_traffic ?? '—',
      suffix: 'Flow Detections',
      detail: 'Lateral SMB, covert C2, port scans',
      icon: Network,
      tone: 'normal',
    },
  ];

  return (
    <div ref={root} className="mx-auto w-full max-w-[1600px] space-y-6">
      {loadError && (
        <div role="status" className="overview-entrance rounded-2xl border border-amber-400/25 bg-amber-400/[0.07] p-4 text-sm text-amber-100">
          <p className="font-semibold">Overview data could not be refreshed.</p>
          <p className="mt-1 text-xs text-slate-300">Showing the last successfully loaded results when available. The existing 10-second refresh will try again.</p>
        </div>
      )}
      {stats?.total_detections === 0 && <div role="status" className="overview-entrance rounded-2xl border border-white/[0.08] bg-[var(--soc-panel)] p-4 text-sm text-slate-300">No detections yet. Ingest an event and run it through the detector to populate this view.</div>}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {kpis.map((kpi, index) => {
          const Icon = kpi.icon;
          const tone = KPI_TONES[index];
          return (
            <Card key={kpi.label} className="overview-entrance group relative min-h-36 overflow-hidden border-white/[0.08] bg-gradient-to-br from-[var(--soc-panel)] to-[var(--soc-raised)] p-5 transition-transform duration-200 hover:-translate-y-0.5">
              <span aria-hidden="true" className="absolute inset-x-5 top-0 h-px opacity-80" style={{ background: `linear-gradient(90deg, transparent, ${tone.accent}, transparent)`, boxShadow: `0 0 18px ${tone.accent}` }} />
              <div className="flex items-start justify-between gap-3">
                <p className="pt-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">{kpi.label}</p>
                <span className={`rounded-xl border border-white/[0.06] p-2.5 ${tone.tone === 'critical' ? 'bg-rose-400/10 text-rose-200' : tone.tone === 'medium' ? 'bg-amber-400/10 text-amber-200' : tone.tone === 'novel' ? 'bg-purple-400/10 text-purple-200' : 'bg-blue-400/10 text-blue-200'}`}>
                  <Icon aria-hidden="true" className="h-4 w-4" />
                </span>
              </div>
              <div className="mt-5 flex min-h-10 items-end justify-between gap-3">
                <CountUpValue value={kpi.value} className="font-[family-name:var(--soc-font-display)] text-3xl font-semibold tracking-tight text-slate-50" />
                {kpi.tag && <Badge tone="novel" className="shrink-0 font-mono">{kpi.tag}</Badge>}
              </div>
            </Card>
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="overview-entrance min-w-0 p-5 sm:p-6 lg:col-span-2 transition-transform duration-200 hover:-translate-y-0.5">
          <div className="mb-5 flex items-center justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Enterprise Risk Score Trend (Last 60 Min)</h2>
              <p className="mt-1 text-xs text-slate-400">Stored incident risk scores over time</p>
            </div>
            <span className="flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-400/20 bg-emerald-400/[0.06] px-2.5 py-1 text-[11px] font-medium text-emerald-200">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" /> API data
            </span>
          </div>
          {riskTrend.length > 0 ? (
            <div className="h-64" aria-label="Risk score trend chart">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={riskTrend} margin={{ top: 10, right: 8, bottom: 0, left: -14 }}>
                  <defs>
                    <linearGradient id={`${chartId}-risk-fill`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--soc-critical)" stopOpacity={0.24} />
                      <stop offset="95%" stopColor="var(--soc-critical)" stopOpacity={0.01} />
                    </linearGradient>
                    <filter id={`${chartId}-risk-glow`} x="-30%" y="-50%" width="160%" height="200%">
                      <feGaussianBlur stdDeviation="3" result="blur" />
                      <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                    </filter>
                  </defs>
                  <CartesianGrid strokeDasharray="3 6" stroke={chartTheme.grid} vertical={false} />
                  <XAxis dataKey="time" tick={{ fill: chartTheme.axis, fontSize: 11, fontFamily: 'var(--soc-font-mono)' }} axisLine={false} tickLine={false} tickMargin={10} />
                  <YAxis domain={[0, 100]} tick={{ fill: chartTheme.axis, fontSize: 11, fontFamily: 'var(--soc-font-mono)' }} axisLine={false} tickLine={false} tickMargin={8} />
                  <Tooltip content={<OverviewTooltip formatter={(value) => [`${value}%`, 'Risk score']} />} cursor={{ stroke: 'rgba(148,163,184,.22)', strokeDasharray: '3 4' }} />
                  <Area type="monotone" dataKey="risk" stroke="none" fill={`url(#${chartId}-risk-fill)`} isAnimationActive={!prefersReducedMotion()} animationDuration={850} />
                  <Line type="monotone" dataKey="risk" stroke="var(--soc-critical)" strokeWidth={2.5} dot={{ r: 3, fill: 'var(--soc-critical)', stroke: 'var(--soc-panel)', strokeWidth: 2 }} activeDot={{ r: 6, fill: 'var(--soc-critical)', stroke: '#fff', strokeWidth: 2 }} filter={`url(#${chartId}-risk-glow)`} isAnimationActive={!prefersReducedMotion()} animationDuration={850} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState
              icon={Activity}
              title={loadError && !stats ? 'Risk trend unavailable' : 'No incidents scored in the last 60 minutes'}
              description={loadError && !stats ? 'Risk trend data will appear when overview data is available.' : 'Stored incident scores will appear here after they are recorded.'}
              className="min-h-64"
            />
          )}
        </Card>

        <Card className="overview-entrance flex min-w-0 flex-col p-5 sm:p-6 transition-transform duration-200 hover:-translate-y-0.5">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Threat Category Breakdown</h2>
            <p className="mt-1 text-xs text-slate-400">MITRE ATT&CK &amp; Open-Set Classification</p>
          </div>
          {threatDistribution.length > 0 ? (
            <>
              <div className="relative mt-2 h-48" aria-label="Threat category breakdown chart">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatDistribution}
                      cx="50%"
                      cy="50%"
                      innerRadius={58}
                      outerRadius={78}
                      paddingAngle={4}
                      dataKey="value"
                      onMouseEnter={(_, index) => setActiveSlice(index)}
                      onMouseLeave={() => setActiveSlice(null)}
                      isAnimationActive={!prefersReducedMotion()}
                      animationDuration={850}
                    >
                      {threatDistribution.map((entry, index) => {
                        const color = categoryColor(entry.name);
                        return <Cell key={`${entry.name}-${index}`} fill={color} fillOpacity={activeSlice == null || activeSlice === index ? 1 : 0.38} stroke="var(--soc-panel)" strokeWidth={2} />;
                      })}
                    </Pie>
                    <Tooltip content={<OverviewTooltip formatter={(value) => [value, 'Detections']} />} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <span className="font-[family-name:var(--soc-font-display)] text-2xl font-semibold text-slate-50">{threatTotal.toLocaleString()}</span>
                  <span className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">Total</span>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {threatDistribution.slice(0, 4).map((item, index) => (
                  <span key={`${item.name}-${index}`} className="inline-flex items-center gap-2 rounded-lg border border-white/[0.07] bg-white/[0.025] px-2.5 py-1.5 text-[11px] text-slate-300">
                    <span aria-hidden="true" className="h-2 w-2 rounded-full" style={{ backgroundColor: categoryColor(item.name) }} />
                    <span>{item.name}</span>
                    <span className="soc-mono text-slate-100">{item.value}</span>
                  </span>
                ))}
              </div>
            </>
          ) : (
            <EmptyState
              icon={ShieldAlert}
              title={loadError && !stats ? 'Threat categories unavailable' : 'No threat categories to display'}
              description={loadError && !stats ? 'Category data will appear when overview data is available.' : 'Categories will appear here when detections are recorded.'}
              className="my-auto min-h-64"
            />
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {layers.map((layer) => {
          const Icon = layer.icon;
          return (
            <Card key={layer.title} className="overview-entrance relative flex min-w-0 items-center gap-4 overflow-hidden p-4 transition-transform duration-200 hover:-translate-y-0.5">
              <span aria-hidden="true" className={`absolute inset-y-4 left-0 w-px ${layer.tone === 'novel' ? 'bg-purple-300/70' : layer.tone === 'normal' ? 'bg-emerald-300/70' : 'bg-blue-300/70'}`} />
              <span className={`ml-1 rounded-xl border border-white/[0.06] p-3 ${layer.tone === 'novel' ? 'bg-purple-400/10 text-purple-200' : layer.tone === 'normal' ? 'bg-emerald-400/10 text-emerald-200' : 'bg-blue-400/10 text-blue-200'}`}>
                <Icon aria-hidden="true" className="h-5 w-5" />
              </span>
              <div className="min-w-0">
                <p className="text-[11px] font-semibold text-slate-400">{layer.title}</p>
                <p className="mt-1 text-lg font-semibold text-slate-100">
                  <CountUpValue value={layer.value} /> <span className="text-sm font-medium text-slate-300">{layer.suffix}</span>
                </p>
                <span className="mt-1 block text-[11px] text-slate-400">{layer.detail}</span>
              </div>
            </Card>
          );
        })}
      </div>

      <Card className="overview-entrance min-w-0 overflow-hidden p-0">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-5 py-4 sm:px-6">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Recent Detection Results</h2>
            <p className="mt-1 text-xs text-slate-400">Real-time open-set inference scores and attack probabilities</p>
          </div>
          <span className="flex items-center gap-1.5 text-[11px] text-slate-400"><Clock3 aria-hidden="true" className="h-3.5 w-3.5" /> Latest detection results</span>
        </div>
        <div className="max-h-[32rem] overflow-auto">
          <table className="w-full min-w-[820px] text-left text-xs">
            <thead className="sticky top-0 z-10 bg-[var(--soc-panel)] text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-400 shadow-[0_1px_0_rgba(255,255,255,.06)]">
              <tr>
                <th scope="col" className="px-4 py-3">Verdict</th>
                <th scope="col" className="px-4 py-3">Threat Category</th>
                <th scope="col" className="px-4 py-3">Layer</th>
                <th scope="col" className="px-4 py-3">Score</th>
                <th scope="col" className="px-4 py-3">Attack Probability</th>
                <th scope="col" className="px-4 py-3">Open-Set Distance</th>
                <th scope="col" className="px-4 py-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.05] text-slate-300">
              {recentAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6">
                    <EmptyState
                      icon={Activity}
                      title={loadError && !stats ? 'Detection results unavailable' : 'No detection results yet'}
                      description={loadError && !stats ? 'Results will appear when overview data is available.' : 'Detection results will appear here when they are recorded.'}
                      className="min-h-28 border-0 bg-transparent py-4"
                    />
                  </td>
                </tr>
              ) : recentAlerts.map((alert) => {
                const verdict = String(alert.verdict || '');
                const probability = alert.attack_probability == null ? null : Number(alert.attack_probability) * 100;
                const date = alert.created_at ? new Date(alert.created_at) : null;
                const validDate = date && !Number.isNaN(date.getTime());
                const flash = flashAlertIds.has(alert.detection_id);
                return (
                  <tr key={alert.detection_id} className="transition-colors duration-150 hover:bg-white/[0.035]">
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><Badge tone={verdictTone(alert.verdict)} className="font-mono text-[11px]">{verdict.replace(/_/g, ' ')}</Badge></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="font-medium text-slate-200">{alert.predicted_class}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="soc-mono uppercase text-slate-400">{alert.layer}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="soc-mono">{alert.score == null ? '—' : alert.score.toFixed(2)}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}>
                      {probability == null || !Number.isFinite(probability) ? <span className="soc-mono text-slate-400">—</span> : (
                        <div className="flex min-w-36 items-center gap-2.5">
                          <span className="soc-mono w-12 shrink-0 text-slate-200">{probability.toFixed(1)}%</span>
                          <span role="progressbar" aria-label={`${probability.toFixed(1)}% attack probability`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.max(0, Math.min(100, probability))} className="h-1.5 w-20 overflow-hidden rounded-full bg-white/[0.08]">
                            <span className="block h-full rounded-full bg-gradient-to-r from-[var(--soc-low)] to-[var(--soc-accent-end)]" style={{ width: `${Math.max(0, Math.min(100, probability))}%` }} />
                          </span>
                        </div>
                      )}
                    </DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="soc-mono text-slate-400">{alert.open_set_distance == null ? '—' : alert.open_set_distance.toFixed(2)}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}>
                      <time className="soc-mono text-slate-400" dateTime={validDate ? date.toISOString() : undefined} title={validDate ? date.toLocaleString() : undefined}>
                        {validDate ? date.toLocaleTimeString() : 'Timestamp unavailable'}
                      </time>
                    </DetectionCell>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
