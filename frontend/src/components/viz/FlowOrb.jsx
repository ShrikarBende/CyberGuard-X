import React, { useId, useRef } from 'react';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../../lib/motion';
import Badge from '../ui/Badge';
import StatCard from '../ui/StatCard';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUS_ORDER = ['OPEN', 'NEEDS_REVIEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CONFIRMED', 'FALSE_POSITIVE'];

function safeCount(value) {
  if (value == null || value === '') return 0;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : 0;
}

function groupCount(rows, field, order) {
  const counts = new Map();
  rows.forEach((row) => {
    const label = typeof row?.[field] === 'string' ? row[field].trim().toUpperCase() : '';
    if (label) counts.set(label, (counts.get(label) || 0) + 1);
  });
  const labels = [...new Set([...order, ...Array.from(counts.keys()).filter((label) => !order.includes(label)).sort()])];
  return labels.map((label) => ({ label, count: counts.get(label) || 0 }));
}

function displayLabel(value) {
  return String(value || '').toLowerCase().replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function OrbCount({ value }) {
  const countRef = useRef(null);
  const animated = useRef(false);
  const count = safeCount(value);

  useGSAP(() => {
    const node = countRef.current;
    if (!node) return undefined;
    if (animated.current) {
      node.textContent = String(count);
      return undefined;
    }

    animated.current = true;
    return createMotionScope(node, (reduced) => {
      const targetNode = countRef.current;
      if (!targetNode) return;
      if (reduced) {
        targetNode.textContent = String(count);
        return;
      }
      const counter = { value: 0 };
      gsap.fromTo(counter, { value: 0 }, {
        value: count,
        duration: motion.duration.entrance,
        ease: motion.easeSoft,
        onUpdate: () => {
          if (countRef.current) countRef.current.textContent = Math.round(counter.value).toLocaleString();
        },
        onComplete: () => {
          if (countRef.current) countRef.current.textContent = String(count);
        },
      });
    });
  }, { scope: countRef, dependencies: [count], revertOnUpdate: false });

  return <text ref={countRef} x="600" y="394" textAnchor="middle" className="fill-slate-50" style={{ fontSize: 64, fontWeight: 300, fontVariantNumeric: 'tabular-nums' }}>{String(count)}</text>;
}

function Ribbon({ targetY, count, sideTotal, color, pathKey }) {
  if (count <= 0) return null;
  const share = sideTotal > 0 ? count / sideTotal : 0;
  const width = 1.5 + share * 14;
  return <path
    data-flow-line="true"
    data-flow-key={pathKey}
    d={`M 775 382 C 824 382, 831 ${targetY}, 880 ${targetY}`}
    fill="none"
    stroke={color}
    strokeWidth={width}
    strokeLinecap="round"
    opacity="0.58"
  />;
}

function CountGroupCard({ x, y, width, title, rows, type, available, loading, capReached, glassId }) {
  const rowStep = type === 'severity' ? 40 : 34;
  const headerHeight = type === 'severity' ? 64 : 58;
  const height = headerHeight + Math.max(rows.length, 1) * rowStep + 18;
  const accent = type === 'severity' ? '#e94759' : '#438cff';
  return <g data-flow-card="true">
    <rect x={x} y={y} width={width} height={height} rx="22" fill={`url(#${glassId})`} stroke="rgba(255,255,255,.12)" />
    <path d={`M ${x + 20} ${y + 1} H ${x + width - 20}`} stroke={accent} strokeOpacity=".55" strokeWidth="2" strokeLinecap="round" />
    <text x={x + 22} y={y + 31} fill="#f3f3fa" fontSize="17" fontWeight="500">{title}</text>
    {capReached && <text x={x + 22} y={y + 49} fill="#b5b3cc" fontSize="12">Returned rows only · 50 row cap reached</text>}
    {!available && <text x={x + 22} y={y + headerHeight + 22} fill="#b5b3cc" fontSize="14">{loading ? 'Loading incident counts…' : 'Incident counts unavailable'}</text>}
    {available && rows.length === 0 && <text x={x + 22} y={y + headerHeight + 22} fill="#b5b3cc" fontSize="14">No incident rows returned</text>}
    {available && rows.map((row, index) => {
      const baseline = y + headerHeight + 25 + index * rowStep;
      const tone = type === 'severity' && row.label === 'CRITICAL' ? '#f1747e' : type === 'severity' && row.label === 'HIGH' ? '#ed8b46' : type === 'severity' && row.label === 'MEDIUM' ? '#e8b84c' : type === 'severity' ? '#8db8ff' : '#b5b3cc';
      return <g key={`${type}-${row.label}`}>
        <circle cx={x + 24} cy={baseline - 5} r="3.5" fill={tone} />
        <text x={x + 38} y={baseline} fill="#c8c6da" fontSize="14">{displayLabel(row.label)}</text>
        <text x={x + width - 22} y={baseline} textAnchor="end" fill="#f3f3fa" fontSize="16" fontWeight="500" style={{ fontVariantNumeric: 'tabular-nums' }}>{row.count}</text>
      </g>;
    })}
  </g>;
}

export default function FlowOrb({ totalEvents, layers = [], incidents, incidentLoadError = false, extraKpis = [] }) {
  const root = useRef(null);
  const reactId = useId();
  const id = `flow-${reactId.replace(/[^a-zA-Z0-9_-]/g, '')}`;
  const total = safeCount(totalEvents);
  const safeLayers = Array.isArray(layers) ? layers.map((layer) => ({
    title: typeof layer?.title === 'string' ? layer.title : 'Layer',
    value: safeCount(layer?.value),
    suffix: typeof layer?.suffix === 'string' ? layer.suffix : 'Detections',
  })) : [];
  const rows = Array.isArray(incidents) ? incidents.filter((incident) => incident && typeof incident === 'object' && !Array.isArray(incident)) : [];
  const available = Array.isArray(incidents) && !incidentLoadError;
  const incidentLoading = incidents == null && !incidentLoadError;
  const capReached = available && rows.length >= 50;
  const severities = groupCount(rows, 'severity', SEVERITY_ORDER);
  const statuses = groupCount(rows, 'status', STATUS_ORDER);
  const severityTotal = severities.reduce((sum, row) => sum + row.count, 0);
  const statusTotal = statuses.reduce((sum, row) => sum + row.count, 0);
  const tickAngles = Array.from({ length: 72 }, (_, index) => index * 5);
  const severityTop = 112;
  const statusTop = 408;
  const severityRowStart = severityTop + 64 + 25;
  const statusRowStart = statusTop + 58 + 25;

  const numberSummary = [
    `Total events analyzed ${total}`,
    ...safeLayers.map((layer) => `${layer.title} ${layer.value} ${layer.suffix}`),
    ...extraKpis.map((item) => `${String(item?.label || 'Overview metric')} ${String(item?.value ?? '—')}`),
    `Incidents by severity${capReached ? ', 50 row cap reached, total may be higher' : ''}: ${available ? (severities.map((row) => `${displayLabel(row.label)} ${row.count}`).join(', ') || 'none returned') : incidentLoading ? 'loading' : 'unavailable'}`,
    `Incidents by status${capReached ? ', 50 row cap reached, total may be higher' : ''}: ${available ? (statuses.map((row) => `${displayLabel(row.label)} ${row.count}`).join(', ') || 'none returned') : incidentLoading ? 'loading' : 'unavailable'}`,
  ].join('. ');

  useGSAP(() => {
    const scope = root.current;
    if (!scope) return undefined;
    return createMotionScope(scope, (reduced) => {
      const lines = Array.from(scope.querySelectorAll('[data-flow-line="true"]'));
      const cards = Array.from(scope.querySelectorAll('[data-flow-card="true"]'));
      if (reduced) return;

      lines.forEach((line) => {
        if (!line || typeof line.getTotalLength !== 'function') return;
        const length = line.getTotalLength();
        if (!Number.isFinite(length) || length <= 0) return;
        gsap.set(line, { strokeDasharray: `${length} ${length}` });
        gsap.fromTo(line, { strokeDashoffset: length }, {
          strokeDashoffset: 0,
          duration: 0.68,
          ease: motion.ease,
          clearProps: 'strokeDasharray,strokeDashoffset',
        });
      });
      if (cards.length) {
        gsap.fromTo(cards, { autoAlpha: 0, y: 8 }, {
          autoAlpha: 1,
          y: 0,
          duration: 0.42,
          stagger: 0.07,
          ease: motion.ease,
          clearProps: 'opacity,visibility,transform',
        });
      }
    });
  }, { scope: root, revertOnUpdate: false });

  const severityPathY = (index) => severityRowStart + index * 40 - 5;
  const statusPathY = (index) => statusRowStart + index * 34 - 5;
  const severityCountValue = available ? severities : [];
  const statusCountValue = available ? statuses : [];

  return <section ref={root} className="overview-entrance space-y-4" aria-label="Overview event flow">
    <div className="soc-card overflow-x-auto rounded-[22px] p-2 sm:p-3">
      <svg role="img" aria-label={numberSummary} viewBox="0 0 1240 760" className="block h-auto min-w-[760px] w-full" preserveAspectRatio="xMidYMid meet">
        <defs>
          <radialGradient id={`${id}-orb-fill`} cx="50%" cy="35%" r="70%">
            <stop offset="0%" stopColor="#11122d" />
            <stop offset="72%" stopColor="#090817" />
            <stop offset="100%" stopColor="#05040d" />
          </radialGradient>
          <linearGradient id={`${id}-ring`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#3050ff" />
            <stop offset="52%" stopColor="#438cff" />
            <stop offset="100%" stopColor="#8b1fd1" />
          </linearGradient>
          <linearGradient id={`${id}-flow-glass`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#18152e" stopOpacity=".95" />
            <stop offset="100%" stopColor="#090817" stopOpacity=".97" />
          </linearGradient>
          <filter id={`${id}-orb-glow`} x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="16" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <text x="46" y="82" fill="#c7c4de" fontSize="14" fontWeight="400">Detection layers</text>
        <text x="885" y="88" fill="#c7c4de" fontSize="13">Incident counts from returned records</text>

        {safeLayers.slice(0, 3).map((layer, index) => {
          const y = 290 + index * 92;
          return <g key={`layer-${layer.title}`}>
            <path data-flow-line="true" d={`M 370 ${y} C 394 ${y}, 405 382, 442 382`} fill="none" stroke="#3050ff" strokeWidth="1.8" strokeOpacity=".76" />
            <circle cx="370" cy={y} r="5" fill="#438cff" stroke="#9ec4ff" strokeWidth="1" />
            <text x="44" y={y - 7} fill="#f3f3fa" fontSize="16" fontWeight="400">{layer.title}</text>
            <text x="44" y={y + 17} fill="#b5b3cc" fontSize="13">{layer.value.toLocaleString()} {layer.suffix}</text>
          </g>;
        })}

        {severityCountValue.map((row, index) => <Ribbon key={`severity-ribbon-${row.label}`} targetY={severityPathY(index)} count={row.count} sideTotal={severityTotal} color={row.label === 'CRITICAL' ? '#e94759' : '#d45a66'} pathKey={`severity-${row.label}`} />)}
        {statusCountValue.map((row, index) => <Ribbon key={`status-ribbon-${row.label}`} targetY={statusPathY(index)} count={row.count} sideTotal={statusTotal} color="#3050ff" pathKey={`status-${row.label}`} />)}

        <g aria-hidden="true">
          <circle cx="600" cy="382" r="198" fill="#3050ff" opacity=".055" filter={`url(#${id}-orb-glow)`} />
          <circle cx="600" cy="382" r="188" fill="none" stroke="rgba(155,157,255,.13)" strokeWidth="1" />
          {tickAngles.map((angle) => <line key={`tick-${angle}`} x1="0" y1="-190" x2="0" y2="-198" transform={`translate(600 382) rotate(${angle})`} stroke="rgba(196,194,255,.48)" strokeWidth="1" />)}
          <circle cx="600" cy="382" r="168" fill="none" stroke={`url(#${id}-ring)`} strokeWidth="5" opacity=".92" />
          <circle cx="600" cy="382" r="153" fill={`url(#${id}-orb-fill)`} stroke="rgba(143,165,255,.3)" strokeWidth="1" />
          <circle cx="600" cy="382" r="138" fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="1" />
        </g>
        <OrbCount value={total} />
        <text x="600" y="428" textAnchor="middle" fill="#c9c6df" fontSize="15">Total Events Analyzed</text>

        <CountGroupCard x={880} y={severityTop} width={350} title="Incidents by severity" rows={available ? severities : []} type="severity" available={available} loading={incidentLoading} capReached={capReached} glassId={`${id}-flow-glass`} />
        <CountGroupCard x={880} y={statusTop} width={350} title="Incidents by status" rows={available ? statuses : []} type="status" available={available} loading={incidentLoading} capReached={capReached} glassId={`${id}-flow-glass`} />
      </svg>
    </div>

    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      {extraKpis.map((kpi) => <StatCard key={kpi.label} label={kpi.label} value={kpi.value} formatValue={(value) => String(value ?? '—')} detail={kpi.tag ? <Badge tone="novel" className="shrink-0">{kpi.tag}</Badge> : null} className="overview-entrance min-h-28 p-4" />)}
    </div>
  </section>;
}
