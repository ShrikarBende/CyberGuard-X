import React, { useEffect, useId, useRef, useState } from 'react';
import {
  Activity,
  Clock3,
  ShieldAlert,
} from '../lib/icons';
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
import RiskTicks from '../components/ui/RiskTicks';
import FlowOrb from '../components/viz/FlowOrb';
import { createMotionScope, motion, prefersReducedMotion } from '../lib/motion';
import { chartTheme } from '../charts/chartTheme';

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
    const displayValue = value == null || (typeof value === 'number' && !Number.isFinite(value)) ? '—' : String(value);
    if (!Number.isFinite(target)) {
      valueRef.current.textContent = displayValue;
      return;
    }

    animated.current = true;
    let firstMotionPass = true;
    return createMotionScope(valueRef.current, (reduced) => {
      if (!firstMotionPass) {
      valueRef.current.textContent = displayValue;
        return;
      }
      firstMotionPass = false;
      if (reduced) {
        valueRef.current.textContent = displayValue;
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
          if (valueRef.current) valueRef.current.textContent = displayValue;
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
    <div className="glass min-w-36 rounded-xl p-3 text-[var(--ink)]">
      {label != null && <p className="mb-2 text-xs font-normal text-[var(--muted)]">{label}</p>}
      <div className="space-y-1.5">
        {payload.map((item, index) => {
          const formatted = formatter ? formatter(item.value, item.name, item) : [item.value, item.name];
          return (
            <div key={`${item.dataKey || item.name}-${index}`} className="flex items-center justify-between gap-5 text-xs">
              <span className="flex items-center gap-2 text-[var(--muted)]"><i aria-hidden="true" className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color || item.fill }} />{formatted[1] || item.name}</span>
              <span className="soc-mono font-medium text-[var(--ink)]">{formatted[0]}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function Overview({ onSelectIncident, onNavigateToIncidents }) {
  const root = useRef(null);
  const previousAlertIds = useRef(null);
  const flashResetTimer = useRef(null);
  const chartId = useId().replace(/:/g, '');
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState(null);
  const [incidentLoadError, setIncidentLoadError] = useState(false);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [flashAlertIds, setFlashAlertIds] = useState(() => new Set());
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null);
  const [activeSlice, setActiveSlice] = useState(null);

  useGSAP(() => {
    const scope = root.current;
    if (!scope || loading) return undefined;
    return createMotionScope(scope, (reduced) => {
      const items = gsap.utils.toArray('.overview-entrance', scope);
      if (!items.length) return;
      gsap.fromTo(items,
        { autoAlpha: 0, y: reduced ? 0 : 12 },
        {
          autoAlpha: 1,
          y: 0,
          duration: reduced ? 0.18 : 0.48,
          stagger: reduced ? 0 : 0.055,
          ease: motion.ease,
          clearProps: 'opacity,transform,visibility',
        },
      );
    });
  }, { scope: root, dependencies: [loading], revertOnUpdate: true });

  useGSAP(() => {
    const scope = root.current;
    if (!scope || !flashAlertIds.size) return undefined;
    return createMotionScope(scope, (reduced) => {
      const overlays = Array.from(scope.querySelectorAll('[data-row-flash-id]'))
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
        setLastUpdatedAt(Date.now());
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

  useEffect(() => {
    let mounted = true;
    api.getIncidents().then((rows) => {
      if (!mounted) return;
      setIncidents(Array.isArray(rows) ? rows : []);
      setIncidentLoadError(false);
    }).catch(() => {
      if (!mounted) return;
      setIncidents(null);
      setIncidentLoadError(true);
    });
    return () => { mounted = false; };
  }, []);

  if (loading && !stats) return <LoadingOverview />;

  const extraKpis = [
    { label: 'Known Threats Detected', value: stats?.known_threats ?? '—' },
    { label: 'Unknown Candidates', value: stats?.unknown_candidates ?? '—', tag: 'Open-Set Gate' },
    { label: 'Critical Incidents', value: stats?.critical_incidents ?? '—' },
  ];
  const riskTrend = stats?.risk_trend || [];
  const threatDistribution = stats?.threat_distribution || [];
  const threatTotal = threatDistribution.reduce((total, item) => total + (Number(item.value) || 0), 0);
  const layers = [
    {
      title: 'User / Identity Layer',
      value: stats?.layer_detection_stats?.user_identity ?? '—',
      suffix: 'Anomaly Flags',
    },
    {
      title: 'Endpoint / Device (Autoencoder + iForest)',
      value: stats?.layer_detection_stats?.endpoint_device ?? '—',
      suffix: 'Process Anomalies',
    },
    {
      title: 'Network Layer (Flows)',
      value: stats?.layer_detection_stats?.network_traffic ?? '—',
      suffix: 'Flow Detections',
    },
  ];

  return (
    <div ref={root} className="mx-auto w-full max-w-[1600px] space-y-6">
      <header className="overview-entrance"><h1 className="font-display text-3xl font-bold leading-tight tracking-tight text-[var(--ink)]">Executive Overview Dashboard</h1><p className="mt-1 text-sm text-[var(--muted)]">Security posture, incident counts, and recent detection results</p></header>
      {loadError && (
        <div role="status" className="overview-entrance rounded-2xl border border-amber-400/25 bg-amber-400/[0.07] p-4 text-sm text-amber-100">
          <p className="font-semibold">Overview data could not be refreshed.</p>
          <p className="mt-1 text-xs text-slate-300">Showing the last successfully loaded results when available. The existing 10-second refresh will try again.</p>
        </div>
      )}
      {lastUpdatedAt && <p className="overview-entrance -mt-3 text-xs text-slate-400" role="status" aria-live="polite">{loadError ? 'Data may be stale · ' : 'Updated · '}{new Date(lastUpdatedAt).toLocaleTimeString()}</p>}
      {stats?.total_detections === 0 && <div role="status" className="overview-entrance rounded-2xl border border-white/[0.08] bg-[var(--soc-panel)] p-4 text-sm text-slate-300">No detections yet. Ingest an event and run it through the detector to populate this view.</div>}

      <FlowOrb totalEvents={stats?.total_events} layers={layers} incidents={incidents} incidentLoadError={incidentLoadError} extraKpis={extraKpis} onReviewIncidents={onNavigateToIncidents} engineStatus={stats?.system_status || '—'} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="overview-entrance min-w-0 p-5 sm:p-6 lg:col-span-2 transition-transform duration-200 hover:-translate-y-0.5">
          <div className="mb-5 flex items-center justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Enterprise Risk Score Trend (Last 60 Min)</h2>
              <p className="mt-1 text-xs text-slate-400">Stored incident risk scores over time</p>
            </div>
            <span className="flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-400/20 bg-emerald-400/[0.06] px-2.5 py-1 text-xs font-medium text-emerald-200">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" /> API data
            </span>
          </div>
          {riskTrend.length > 0 ? (
            <div className="h-64" aria-label="Risk score trend chart">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={riskTrend} margin={{ top: 10, right: 8, bottom: 0, left: -14 }}>
                  <defs>
                  </defs>
                  <CartesianGrid strokeDasharray="3 6" stroke={chartTheme.grid} vertical={false} />
                  <XAxis dataKey="time" tick={{ fill: chartTheme.axis, fontSize: 11, fontFamily: 'var(--soc-font-mono)' }} axisLine={false} tickLine={false} tickMargin={10} />
                  <YAxis domain={[0, 100]} tick={{ fill: chartTheme.axis, fontSize: 11, fontFamily: 'var(--soc-font-mono)' }} axisLine={false} tickLine={false} tickMargin={8} />
                  <Tooltip content={<OverviewTooltip formatter={(value) => [`${value}%`, 'Risk score']} />} cursor={{ stroke: 'rgba(148,163,184,.22)', strokeDasharray: '3 4' }} />
                  <Area type="monotone" dataKey="risk" stroke="none" fill="rgba(37,53,240,.11)" isAnimationActive={!prefersReducedMotion()} animationDuration={400} />
                  <Line type="monotone" dataKey="risk" stroke="var(--cobalt)" strokeWidth={2} dot={{ r: 3, fill: 'var(--cobalt)', stroke: 'var(--card)', strokeWidth: 2 }} activeDot={{ r: 6, fill: 'var(--cobalt)', stroke: '#fff', strokeWidth: 2 }} isAnimationActive={!prefersReducedMotion()} animationDuration={400} />
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
            threatDistribution.length <= 6 ? <div className="mt-6 space-y-5" aria-label="Threat category breakdown chart">
              {threatDistribution.map((item, index) => {
                const maxValue = Math.max(1, ...threatDistribution.map((entry) => Number(entry.value) || 0));
                const width = Math.max(0, Math.min(100, ((Number(item.value) || 0) / maxValue) * 100));
                return <div key={`${item.name}-${index}`}>
                  <div className="mb-2 flex items-center justify-between gap-3 text-sm"><span className="text-[var(--muted)]">{item.name}</span><span className="soc-mono text-[var(--ink)]">{item.value}</span></div>
                  <div className="h-2 overflow-hidden rounded-full bg-[var(--line)]"><div className="h-full rounded-full" style={{ width: `${width}%`, backgroundColor: categoryColor(item.name) }} /></div>
                </div>;
              })}
            </div> : (
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
                      animationDuration={400}
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
                  <span className="mt-0.5 text-xs font-normal text-slate-300">Total</span>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {threatDistribution.slice(0, 4).map((item, index) => (
                      <span key={`${item.name}-${index}`} className="inline-flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--chip)] px-2.5 py-1.5 text-xs text-[var(--muted)]">
                    <span aria-hidden="true" className="h-2 w-2 rounded-full" style={{ backgroundColor: categoryColor(item.name) }} />
                    <span>{item.name}</span>
                    <span className="soc-mono text-slate-100">{item.value}</span>
                  </span>
                ))}
              </div>
            </>
            )
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

      <Card className="overview-entrance min-w-0 overflow-hidden p-0">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-5 py-4 sm:px-6">
          <div>
            <h2 className="text-xl font-light text-slate-100">Recent Detection Results</h2>
            <p className="mt-1 text-sm font-normal text-slate-300">Real-time open-set inference scores and attack probabilities</p>
          </div>
          <span className="flex items-center gap-1.5 text-xs text-slate-400"><Clock3 aria-hidden="true" className="h-3.5 w-3.5" /> Latest detection results</span>
        </div>
        <div className="max-h-[32rem] overflow-auto overscroll-contain">
          <table className="w-full min-w-[980px] border-separate border-spacing-y-1.5 text-left text-sm">
            <thead className="sticky top-0 z-10 bg-[var(--soc-panel)] text-xs font-normal text-slate-300 shadow-[0_1px_0_rgba(255,255,255,.06)]">
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
            <tbody className="text-slate-200">
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
                  <tr key={alert.detection_id} className="soc-table-row">
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><Badge tone={verdictTone(alert.verdict)} className="text-xs">{verdict.replace(/_/g, ' ')}</Badge></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="font-medium text-slate-200">{alert.predicted_class}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="soc-mono text-slate-300">{alert.layer}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="tabular-nums">{alert.score == null || !Number.isFinite(Number(alert.score)) ? '—' : Number(alert.score).toFixed(2)}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}>
                      <RiskTicks value={probability} />
                    </DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}><span className="tabular-nums text-slate-300">{alert.open_set_distance == null || !Number.isFinite(Number(alert.open_set_distance)) ? '—' : Number(alert.open_set_distance).toFixed(2)}</span></DetectionCell>
                    <DetectionCell detectionId={alert.detection_id} flash={flash}>
                      <time className="text-slate-300" dateTime={validDate ? date.toISOString() : undefined} title={validDate ? date.toLocaleString() : undefined}>
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
