import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { api } from '../../services/api';
import { createMotionScope, motion } from '../../lib/motion';
import Card from '../ui/Card';
import EmptyState from '../ui/EmptyState';
import ErrorState from '../ui/ErrorState';
import GlassTooltip from '../ui/GlassTooltip';
import Skeleton from '../ui/Skeleton';

const VERDICTS = ['BENIGN', 'KNOWN_THREAT', 'UNKNOWN_CANDIDATE', 'UNKNOWN_NOVEL'];
const MAX_DOTS = 300;
const KNOWN_COLORS = ['#2F6FED', '#2535F0', '#7C3AED', '#0B7F4F', '#C98A0B'];
const RING_COUNT = 6;
const CENTER = { x: 380, y: 280 };
const INNER_RADIUS = 78;
const OUTER_RADIUS = 224;

function finiteNumber(value) {
  const number = Number(value);
  return value != null && Number.isFinite(number) ? number : null;
}

function groupKey(row) {
  if (row.verdict === 'KNOWN_THREAT') return `known:${row.predicted_class || 'Unknown class'}`;
  return String(row.verdict || 'OTHER');
}

function displayName(row) {
  if (row.verdict === 'KNOWN_THREAT') return `Known · ${row.predicted_class || 'Unknown class'}`;
  return row.verdict || 'Unknown verdict';
}

function stableSample(rows, limit) {
  if (rows.length <= limit) return rows;
  const groups = new Map();
  rows.forEach((row) => {
    const key = groupKey(row);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  });
  const sortedGroups = [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  const allocations = sortedGroups.map(([key, group]) => {
    const exact = (group.length / rows.length) * limit;
    return { key, group, count: Math.floor(exact), remainder: exact - Math.floor(exact) };
  });
  let remaining = limit - allocations.reduce((sum, item) => sum + item.count, 0);
  allocations.slice().sort((a, b) => b.remainder - a.remainder || a.key.localeCompare(b.key)).forEach((item) => {
    if (remaining > 0 && item.count < item.group.length) {
      item.count += 1;
      remaining -= 1;
    }
  });
  const sampled = [];
  allocations.forEach(({ group, count }) => {
    const ordered = group.slice().sort((a, b) => String(a.detection_id).localeCompare(String(b.detection_id)));
    for (let index = 0; index < count; index += 1) {
      const sourceIndex = Math.min(ordered.length - 1, Math.floor(((index + 0.5) * ordered.length) / count));
      sampled.push(ordered[sourceIndex]);
    }
  });
  return sampled;
}

function formatDate(value) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleString();
}

function formatValue(value, digits = 2) {
  const number = finiteNumber(value);
  return number == null ? 'Unavailable' : number.toFixed(digits);
}

const DistanceSvg = React.memo(function DistanceSvg({ bands, included, count, summaryText, onHover }) {
  return <svg viewBox="0 0 760 560" role="img" aria-label={`Distance map of ${count} detections. ${summaryText}. Each point's angle only spreads detections in chronological order.`} className="block h-auto w-[min(26rem,90vw)] overflow-visible">
    {bands.map((band) => <circle key={`ring-${band.index}`} cx={CENTER.x} cy={CENTER.y} r={band.radius} fill="none" stroke="#E3E6EE" strokeWidth="1" />)}
    <circle cx={CENTER.x} cy={CENTER.y} r="70" fill="#FFFFFF" stroke="#E3E6EE" strokeWidth="1.5" />
    {Array.from({ length: 72 }, (_, index) => {
      const angle = (index / 72) * Math.PI * 2;
      const inner = index % 3 === 0 ? 237 : 239;
      const outer = 245;
      return <line key={`tick-${index}`} x1={CENTER.x + Math.cos(angle) * inner} y1={CENTER.y + Math.sin(angle) * inner} x2={CENTER.x + Math.cos(angle) * outer} y2={CENTER.y + Math.sin(angle) * outer} stroke="rgba(160,160,210,0.20)" strokeWidth="1" />;
    })}
    {Array.from({ length: RING_COUNT }, (_, ring) => <g key={`ring-dots-${ring}`} data-distance-ring="true">
      {included.filter((dot) => dot.ring === ring).map((dot) => <circle key={dot.row.detection_id} data-detection-class={dot.classKey} cx={dot.x} cy={dot.y} r={dot.size} fill={dot.color} fillOpacity="0.92" stroke="rgba(255,255,255,0.2)" strokeWidth="0.7" onMouseEnter={() => onHover(dot)} onMouseLeave={(event) => { if (!event.relatedTarget?.closest?.('[data-detection-class]')) onHover(null); }} />)}
    </g>)}
    <text x={CENTER.x} y={CENTER.y - 2} textAnchor="middle" fill="#12141C" fontSize="34" fontWeight="700" fontFamily="var(--soc-font-display)">{count}</text>
    <text x={CENTER.x} y={CENTER.y + 21} textAnchor="middle" fill="#5B6072" fontSize="12" fontFamily="var(--soc-font-body)">Detections plotted</text>
  </svg>;
});

const DistanceHoverMap = React.memo(function DistanceHoverMap({ bands, included, count, summaryText }) {
  const [hovered, setHovered] = useState(null);
  const handleHover = useCallback((dot) => {
    setHovered((current) => current?.row.detection_id === dot?.row.detection_id ? current : dot);
  }, []);
  const tooltipLabel = hovered ? <dl className="grid grid-cols-[auto_auto] gap-x-3 gap-y-1 text-left text-xs">
    <dt className="text-slate-400">Class</dt><dd>{hovered.row.predicted_class || 'Unavailable'}</dd>
    <dt className="text-slate-400">Verdict</dt><dd>{hovered.row.verdict || 'Unavailable'}</dd>
    <dt className="text-slate-400">Open-set distance</dt><dd className="font-mono tabular-nums">{formatValue(hovered.row.open_set_distance)}</dd>
    <dt className="text-slate-400">Attack probability</dt><dd className="font-mono tabular-nums">{formatValue(hovered.row.attack_probability, 4)}</dd>
    <dt className="text-slate-400">Time</dt><dd>{formatDate(hovered.row.created_at)}</dd>
    <dt className="text-slate-400">Detection ID</dt><dd className="max-w-48 truncate font-mono">{String(hovered.row.detection_id || 'Unavailable')}</dd>
  </dl> : <span className="text-xs text-slate-300">Hover a detection for its recorded fields.</span>;

  return <GlassTooltip label={tooltipLabel}>
    <DistanceSvg bands={bands} included={included} count={count} summaryText={summaryText} onHover={handleHover} />
  </GlassTooltip>;
});

export default function DistanceMap() {
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [visibleClasses, setVisibleClasses] = useState(null);
  const rootRef = useRef(null);
  const entrancePlayed = useRef(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setLoadError(false);
    Promise.all(VERDICTS.map((verdict) => api.getAlerts(verdict, 500)))
      .then((responses) => {
        if (!active) return;
        const unique = new Map();
        responses.flatMap((response) => Array.isArray(response) ? response : []).forEach((row) => {
          if (!row || typeof row !== 'object' || row.detection_id == null) return;
          if (!unique.has(String(row.detection_id))) unique.set(String(row.detection_id), row);
        });
        const usable = [...unique.values()].filter((row) => finiteNumber(row.open_set_distance) != null);
        setDetections(usable);
      })
      .catch((error) => {
        if (!active) return;
        setLoadError(true);
        console.error('Failed to load detection distances:', error);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [retry]);

  const plotData = useMemo(() => {
    const sampled = stableSample(detections, MAX_DOTS);
    if (!sampled.length) return { dots: [], legend: [], bands: [], count: 0, total: detections.length };
    const chronological = sampled.slice().sort((a, b) => {
      const timeA = new Date(a.created_at || 0).getTime();
      const timeB = new Date(b.created_at || 0).getTime();
      return timeA - timeB || String(a.detection_id).localeCompare(String(b.detection_id));
    });
    const distances = chronological.map((row) => finiteNumber(row.open_set_distance)).filter((value) => value != null);
    const min = Math.min(...distances);
    const max = Math.max(...distances);
    const span = max - min;
    const knownClasses = [...new Set(chronological.filter((row) => row.verdict === 'KNOWN_THREAT').map((row) => row.predicted_class || 'Unknown class'))].sort((a, b) => a.localeCompare(b));
    const classColors = new Map(knownClasses.map((name, index) => [name, KNOWN_COLORS[index % KNOWN_COLORS.length]]));
    const counts = new Map();
    const ringMembers = Array.from({ length: RING_COUNT }, () => []);
    chronological.forEach((row) => {
      const distance = finiteNumber(row.open_set_distance);
      const normalized = span > 0 ? Math.max(0, Math.min(1, (distance - min) / span)) : 0.5;
      const ring = Math.min(RING_COUNT - 1, Math.floor(normalized * RING_COUNT));
      ringMembers[ring].push({ row, distance, normalized, ring, classKey: groupKey(row) });
    });
    const dots = ringMembers.flatMap((members, ring) => members.map((dot, index) => {
      const angle = -Math.PI / 2 + ((index + 0.5) / Math.max(1, members.length)) * Math.PI * 2;
      const radius = INNER_RADIUS + dot.normalized * (OUTER_RADIUS - INNER_RADIUS);
      const isKnown = dot.row.verdict === 'KNOWN_THREAT';
      const color = dot.row.verdict === 'BENIGN' ? '#0B7F4F'
        : dot.row.verdict === 'UNKNOWN_CANDIDATE' ? '#C98A0B'
          : dot.row.verdict === 'UNKNOWN_NOVEL' ? '#7C3AED'
            : isKnown ? classColors.get(dot.row.predicted_class || 'Unknown class') : '#8A8FA3';
      const probability = finiteNumber(dot.row.attack_probability);
      const normalizedProbability = probability == null ? null : Math.max(0, Math.min(1, probability > 1 ? probability / 100 : probability));
      const item = {
        ...dot,
        color,
        x: CENTER.x + Math.cos(angle) * radius,
        y: CENTER.y + Math.sin(angle) * radius,
        size: normalizedProbability == null ? 4 : 3 + normalizedProbability * 3.5,
        name: displayName(dot.row),
      };
      counts.set(item.classKey, (counts.get(item.classKey) || 0) + 1);
      return item;
    }));
    const legend = [...counts.entries()].map(([key, count]) => {
      const row = chronological.find((item) => groupKey(item) === key);
      return { key, count, name: row ? displayName(row) : key, color: dots.find((item) => item.classKey === key)?.color || '#94a3b8' };
    });
    const bands = Array.from({ length: RING_COUNT }, (_, index) => {
      const start = min + (span * index) / RING_COUNT;
      const end = min + (span * (index + 1)) / RING_COUNT;
      return { index, radius: INNER_RADIUS + ((index + 1) / RING_COUNT) * (OUTER_RADIUS - INNER_RADIUS), label: span > 0 ? `${start.toFixed(2)}–${end.toFixed(2)}` : min.toFixed(2) };
    });
    return { dots, legend, bands, count: dots.length, total: detections.length };
  }, [detections]);

  useEffect(() => createMotionScope(rootRef, (reduced) => {
    const root = rootRef.current;
    if (!root || loading || loadError || !plotData.dots.length || entrancePlayed.current || reduced) return;
    const rings = root.querySelectorAll('[data-distance-ring]');
    if (!rings.length) return;
    entrancePlayed.current = true;
    gsap.fromTo(rings, { opacity: 0, scale: 0.94, transformOrigin: 'center center' }, {
      opacity: 1, scale: 1, duration: 0.42, ease: motion.ease,
      stagger: { each: 0.09 }, clearProps: 'all',
    });
  }), [loading, loadError, plotData]);

  const legendKeys = plotData.legend.map((item) => item.key);
  const allVisible = visibleClasses == null || visibleClasses.size === legendKeys.length;
  const included = useMemo(() => plotData.dots.filter((dot) => allVisible || visibleClasses?.has(dot.classKey)), [plotData.dots, allVisible, visibleClasses]);
  const toggleClass = (key) => setVisibleClasses((current) => {
    const next = new Set(current == null ? legendKeys : current);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next.size === legendKeys.length ? null : next;
  });
  if (loading) return <div aria-busy="true" className="space-y-4 rounded-[22px] border border-white/[0.08] bg-[var(--soc-raised)] p-5"><Skeleton className="h-7 w-48" /><Skeleton className="h-[28rem] w-full" /><Skeleton className="h-10 w-full" /></div>;
  if (loadError) return <ErrorState title="Distance data could not be loaded" description="The detection distance query failed." onRetry={() => setRetry((value) => value + 1)} />;
  if (!plotData.dots.length) return <EmptyState title="No detection distances available" description="No returned detections include a usable open-set distance." className="bg-[var(--soc-raised)]" />;

  const summaryText = plotData.legend.map((item) => `${item.name}: ${item.count}`).join(', ');
  return <div ref={rootRef} className="space-y-4">
    <Card className="overflow-visible p-4 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="text-2xl font-light text-slate-100">Open-set distance map</h2><p className="mt-1 text-sm text-slate-300">Detections arranged by their recorded open-set distance.</p></div>
        <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.06] to-white/[0.02] px-4 py-2 text-right"><div className="text-3xl font-light tabular-nums text-slate-50">{plotData.count}</div><div className="text-xs text-slate-300">Detections plotted</div></div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2" aria-label="Toggle distance map classes">
        {plotData.legend.map((item) => {
          const enabled = allVisible || visibleClasses?.has(item.key);
          return <button key={item.key} type="button" aria-pressed={enabled} onClick={() => toggleClass(item.key)} className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition-colors ${enabled ? 'border-white/15 bg-white/[0.05] text-slate-100' : 'border-white/[0.06] bg-transparent text-slate-400 opacity-60'}`}><span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }} />{item.name}<span className="font-mono tabular-nums text-slate-300">{item.count}</span></button>;
        })}
      </div>
      <div className="mt-4 rounded-[var(--r-inner)] border border-[var(--line)] bg-[var(--chip)] p-2 sm:p-4">
        <DistanceHoverMap bands={plotData.bands} included={included} count={plotData.count} summaryText={summaryText} />
      </div>
      <p className="mt-3 text-xs text-slate-300">Angle only spreads detections in chronological order; it carries no other meaning.</p>
      {plotData.total > MAX_DOTS && <p className="mt-1 text-xs text-slate-300">Showing {MAX_DOTS} of {plotData.total}</p>}
      <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2" aria-label="Open-set distance ring ranges">
        {plotData.bands.map((band) => <span key={`band-label-${band.index}`} className="inline-flex items-center gap-1.5 text-xs text-slate-300"><span className="inline-block h-px w-3 bg-indigo-300/50" />Ring {band.index + 1}: <span className="font-mono tabular-nums">{band.label}</span></span>)}
      </div>
      <p className="sr-only">Detection counts by class: {summaryText}</p>
    </Card>
  </div>;
}
