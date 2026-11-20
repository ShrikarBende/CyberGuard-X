import React, { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Copy, Cpu, Layers, ShieldAlert } from 'lucide-react';
import { gsap } from 'gsap';
import { api } from '../services/api';
import { createMotionScope, motion, prefersReducedMotion } from '../lib/motion';
import Badge from '../components/ui/Badge';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import Skeleton from '../components/ui/Skeleton';
import StatTile from '../components/ui/StatTile';

const MitreMatrix = lazy(() => import('../components/MitreMatrix'));

export default function ThreatIntelligence() {
  const [threatData, setThreatData] = useState(null);
  const [novelAlerts, setNovelAlerts] = useState([]);
  const [novelOnly, setNovelOnly] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [copiedEvent, setCopiedEvent] = useState('');
  const rootRef = useRef(null);
  const entrancePlayed = useRef(false);
  const countsPlayed = useRef(false);

  useEffect(() => {
    async function loadData() {
      try {
        const [data, novel] = await Promise.all([api.getThreats(), api.getAlerts('UNKNOWN_NOVEL', 100)]);
        setThreatData(data);
        setNovelAlerts(novel);
      } catch (err) {
        setLoadError(true);
        console.error('Failed to load threat intelligence:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  useEffect(() => createMotionScope(rootRef, (reduced) => {
    const root = rootRef.current;
    if (!root || activeTab !== 'overview' || loading || entrancePlayed.current) return;
    const items = root.querySelectorAll('[data-threat-entrance]');
    if (!items.length) return;
    entrancePlayed.current = true;
    gsap.set(items, { opacity: 0, y: reduced ? 0 : 12 });
    gsap.to(items, { opacity: 1, y: 0, duration: reduced ? 0.2 : 0.48, ease: motion.ease, stagger: reduced ? 0 : 0.055, clearProps: 'all' });
  }), [activeTab, loading]);

  useEffect(() => {
    if (loading || activeTab !== 'overview' || countsPlayed.current) return;
    const root = rootRef.current;
    if (!root) return;
    const counters = [...root.querySelectorAll('[data-count-to]')];
    if (!counters.length) return;
    countsPlayed.current = true;
    if (prefersReducedMotion()) {
      counters.forEach((node) => { node.textContent = `${Number(node.dataset.countTo).toFixed(Number(node.dataset.countDecimals || 0))}${node.dataset.countSuffix || ''}`; });
      return;
    }
    const ctx = gsap.context(() => counters.forEach((node) => {
      const target = Number(node.dataset.countTo);
      const decimals = Number(node.dataset.countDecimals || 0);
      const suffix = node.dataset.countSuffix || '';
      const counter = { value: 0 };
      gsap.to(counter, { value: target, duration: 0.75, ease: motion.ease, onUpdate: () => { node.textContent = `${counter.value.toFixed(decimals)}${suffix}`; }, onComplete: () => { node.textContent = `${target.toFixed(decimals)}${suffix}`; } });
    }), root);
    return () => ctx.revert();
  }, [activeTab, loading, threatData]);

  const { summary, known_categories } = threatData || {};
  const visibleNovel = novelOnly ? novelAlerts : (threatData?.unknown_candidates || []);
  const candidateRate = summary?.candidate_rate;
  const copyEvent = async (id) => {
    if (!id || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(id);
      setCopiedEvent(id);
      window.setTimeout(() => setCopiedEvent(''), 1400);
    } catch { /* Clipboard availability varies by browser context. */ }
  };
  const countValue = (value, decimals = 0, suffix = '') => value == null ? '—' : <span data-count-to={value} data-count-decimals={decimals} data-count-suffix={suffix} className="tabular-nums">{`${Number(value).toFixed(decimals)}${suffix}`}</span>;

  return (
    <div ref={rootRef} className="mx-auto w-full max-w-[1600px] space-y-5">
      <div role="tablist" aria-label="Threat intelligence views" onKeyDown={(event) => {
        if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
        event.preventDefault();
        setActiveTab((current) => current === 'overview' ? 'mitre' : 'overview');
        event.currentTarget.querySelector(`[data-view-tab="${activeTab === 'overview' ? 'mitre' : 'overview'}"]`)?.focus();
      }} className="relative flex w-full max-w-md border-b border-white/[0.08]">
        <span aria-hidden="true" className={`pointer-events-none absolute bottom-0 left-0 h-0.5 w-1/2 bg-gradient-to-r from-blue-400 to-violet-400 transition-transform duration-200 ${activeTab === 'mitre' ? 'translate-x-full' : ''}`} />
        <button type="button" id="threat-overview-tab" role="tab" aria-controls="threat-overview-panel" data-view-tab="overview" aria-selected={activeTab === 'overview'} tabIndex={activeTab === 'overview' ? 0 : -1} onClick={() => setActiveTab('overview')} className={`flex-1 px-3 py-2.5 text-xs font-semibold transition-colors ${activeTab === 'overview' ? 'text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}>Threat intelligence</button>
        <button type="button" id="threat-mitre-tab" role="tab" aria-controls="threat-mitre-panel" data-view-tab="mitre" aria-selected={activeTab === 'mitre'} tabIndex={activeTab === 'mitre' ? 0 : -1} onClick={() => setActiveTab('mitre')} className={`flex-1 px-3 py-2.5 text-xs font-semibold transition-colors ${activeTab === 'mitre' ? 'text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}>MITRE ATT&amp;CK</button>
      </div>
      {activeTab === 'mitre' ? <div id="threat-mitre-panel" role="tabpanel" aria-labelledby="threat-mitre-tab"><Suspense fallback={<div aria-busy="true" className="space-y-3 rounded-2xl border border-white/[0.08] bg-[var(--soc-raised)] p-5"><Skeleton className="h-4 w-44" /><Skeleton className="h-24" /></div>}><MitreMatrix /></Suspense></div>
        : loading && !threatData ? <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab" aria-busy="true" className="grid gap-5"><Skeleton className="h-48 rounded-2xl" /><div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((item) => <Skeleton key={item} className="h-32 rounded-2xl" />)}</div><Skeleton className="h-72 rounded-2xl" /></div>
        : loadError && !threatData ? <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab"><EmptyState icon={ShieldAlert} title="Threat intelligence data is unavailable" description="Threat intelligence could not be loaded. Please try again later." className="bg-[var(--soc-raised)]" /></div>
          : <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab" className="space-y-6">
            <section data-threat-entrance className="relative overflow-hidden rounded-2xl border border-purple-400/25 bg-[radial-gradient(ellipse_at_top_right,rgba(168,85,247,0.13),transparent_56%),var(--soc-raised)] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div><p className="text-[11px] font-bold uppercase tracking-[0.16em] text-purple-300">Open-set triage</p><h2 className="mt-1 text-base font-bold text-slate-100">Unknown / Novel Threat View</h2><p className="mt-1 text-xs text-slate-400">Review behavior that falls outside known-class confidence or centroid boundaries.</p></div>
                <label className="inline-flex cursor-pointer items-center gap-2.5 rounded-xl border border-white/[0.08] bg-black/15 px-3 py-2 text-xs text-slate-300"><input type="checkbox" checked={novelOnly} onChange={(event) => setNovelOnly(event.target.checked)} className="peer sr-only" /><span aria-hidden="true" className="relative h-5 w-9 rounded-full bg-slate-600 transition-colors peer-checked:bg-purple-500 peer-focus-visible:ring-2 peer-focus-visible:ring-purple-300 peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-slate-950 after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition-transform peer-checked:after:translate-x-4" />UNKNOWN_NOVEL only</label>
              </div>
              <div className="mt-4 rounded-xl border border-purple-400/20 bg-black/20 p-3 text-sm font-bold text-purple-100">Novel / Unfamiliar Behavior — Requires Analyst Triage</div>
              <div className="mt-3 grid gap-2">
                {visibleNovel.map((item) => {
                  const distance = item.centroid_distance ?? item.open_set_distance;
                  const novelty = item.novelty_score ?? item.details?.open_set_score;
                  const eventId = item.event_id;
                  const score = novelty == null || !Number.isFinite(Number(novelty)) ? null : Number(novelty);
                  return <article key={item.detection_id || item.event_id} className="rounded-xl border border-purple-300/10 bg-slate-950/25 p-3 transition-colors hover:border-purple-300/25 hover:bg-slate-950/40 sm:p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Badge tone="novel">{item.verdict || 'UNKNOWN_NOVEL'}</Badge><span className="font-mono text-[11px] tabular-nums text-slate-400">Event {eventId?.slice(-10) || '—'}</span>{eventId && <button type="button" aria-label={`Copy event ID ${eventId}`} onClick={() => copyEvent(eventId)} className="rounded-md p-1 text-slate-400 hover:bg-white/[0.06] hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple-300"><Copy className="h-3.5 w-3.5" /></button>}{copiedEvent === eventId && <span className="text-[11px] text-emerald-300">Copied</span>}</div><p className="mt-2 text-[11px] text-slate-400">{item.timestamp || item.created_at ? new Date(item.timestamp || item.created_at).toLocaleString() : 'Timestamp unavailable'}</p></div>
                      <div className="flex flex-wrap gap-2"><span className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1.5 text-[11px] text-slate-300">Centroid distance <strong className="ml-1 font-mono tabular-nums text-amber-200">{distance == null ? '—' : Number(distance).toFixed(4)}</strong></span></div></div>
                    <div className="mt-3 max-w-xl"><div className="mb-1.5 flex items-center justify-between text-[11px]"><span className="text-slate-400">Novelty score</span><strong className="font-mono tabular-nums text-purple-200">{score == null ? '—' : score.toFixed(3)}</strong></div><div className="h-1.5 overflow-hidden rounded-full bg-white/[0.07]"><div className="h-full rounded-full bg-gradient-to-r from-purple-500 to-violet-300 transition-[width] duration-300" style={{ width: `${score == null ? 0 : Math.max(0, Math.min(1, score)) * 100}%` }} /></div></div>
                  </article>;
                })}
                {visibleNovel.length === 0 && <p className="py-3 text-xs text-slate-400">No UNKNOWN_NOVEL detections are currently recorded.</p>}
              </div>
            </section>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div data-threat-entrance><StatTile label="Total Detections" icon={Layers} tone="low" value={countValue(summary?.total_detections)} className="border-t-2 border-t-blue-400/50" /></div>
              <div data-threat-entrance><StatTile label="Known Attacks (Supervised)" icon={ShieldAlert} tone="medium" value={countValue(summary?.known_threats_count)} className="border-t-2 border-t-amber-400/50" /></div>
              <div data-threat-entrance><StatTile label="Unknown Candidates" icon={AlertTriangle} tone="novel" value={countValue(summary?.unknown_candidates_count)} className="border-t-2 border-t-purple-400/50" /></div>
              <div data-threat-entrance><StatTile label="Candidate Rate" icon={Cpu} tone="normal" value={countValue(candidateRate == null ? null : candidateRate * 100, 1, '%')} detail={<div className="h-1.5 w-20 overflow-hidden rounded-full bg-white/[0.07]" role="progressbar" aria-label="Candidate Rate" aria-valuemin="0" aria-valuemax="100" aria-valuenow={candidateRate == null ? undefined : Math.max(0, Math.min(100, candidateRate * 100))}><div className="h-full rounded-full bg-emerald-400" style={{ width: `${candidateRate == null ? 0 : Math.max(0, Math.min(1, candidateRate)) * 100}%` }} /></div>} className="border-t-2 border-t-emerald-400/50" /></div>
            </div>

            <div className="grid gap-5 lg:grid-cols-2">
              <Card data-threat-entrance className="p-5 sm:p-6">
                <div className="mb-4 flex items-center gap-3"><div className="rounded-xl border border-amber-400/15 bg-amber-400/10 p-2.5 text-amber-200"><ShieldAlert className="h-5 w-5" /></div><div><h3 className="text-sm font-bold text-slate-100">Classified Known Attack Families</h3><p className="text-xs text-slate-400">CICIDS2017 LightGBM classifier</p></div></div>
                <div className="space-y-2">{(known_categories || []).map((cat, idx) => <div key={idx} className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-black/15 p-3.5 transition-colors hover:border-white/[0.12] hover:bg-white/[0.025]"><div><p className="text-xs font-semibold text-slate-200">{cat}</p><p className="mt-1 text-[11px] text-slate-400">Model class exceeded its configured logit-margin threshold</p></div><Badge tone="medium">CLASSIFIED</Badge></div>)}{(known_categories || []).length === 0 && <EmptyState icon={CheckCircle2} title="No known attack families" description="No classified attack families are present in the current threat data." />}</div>
              </Card>
              <Card data-threat-entrance className="p-5 sm:p-6">
                <div className="mb-4 flex items-center gap-3"><div className="rounded-xl border border-purple-400/15 bg-purple-400/10 p-2.5 text-purple-200"><AlertTriangle className="h-5 w-5" /></div><div><h3 className="text-sm font-bold text-slate-100">Unconfirmed Candidate Queue</h3><p className="text-xs text-slate-400">Flows rejected by the known-validation score threshold; candidates need analyst review</p></div></div>
                <div className="space-y-2">{(threatData?.unknown_candidates || []).slice(0, 4).map((th, idx) => <div key={idx} className="flex items-center justify-between gap-3 rounded-xl border border-purple-300/10 bg-purple-950/10 p-3.5 transition-colors hover:border-purple-300/20 hover:bg-purple-950/20"><div><div className="flex items-center gap-2"><Badge tone="novel">Unconfirmed candidate</Badge><span className="font-mono text-[11px] tabular-nums text-slate-400">#{th.event_id?.slice(-6)}</span></div><p className="mt-1.5 text-[11px] text-slate-400">Latent Distance: <span className="font-mono font-bold tabular-nums text-purple-200">{th.open_set_distance?.toFixed(2) ?? '—'}</span></p></div><div className="text-right"><span className={`font-mono text-[11px] font-bold ${th.reconstruction_error == null ? 'text-slate-500' : 'text-slate-300'}`}>Recon Err: {th.reconstruction_error?.toFixed(3) ?? '—'}</span><p className="mt-1 text-[11px] text-slate-400">{th.timestamp ? new Date(th.timestamp).toLocaleTimeString() : 'Timestamp unavailable'}</p></div></div>)}{(threatData?.unknown_candidates || []).length === 0 && <EmptyState icon={AlertTriangle} title="No unconfirmed candidates" description="No candidate flows are currently recorded in this queue." />}</div>
              </Card>
            </div>
          </div>}
    </div>
  );
}
