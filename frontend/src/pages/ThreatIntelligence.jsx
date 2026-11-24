import React, { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Copy, ShieldAlert } from '../lib/icons';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { api } from '../services/api';
import { createMotionScope, motion } from '../lib/motion';
import Badge from '../components/ui/Badge';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import Skeleton from '../components/ui/Skeleton';
import StatCard from '../components/ui/StatCard';
import Toggle from '../components/ui/Toggle';

const MitreMatrix = lazy(() => import('../components/MitreMatrix'));
const DistanceMap = lazy(() => import('../components/viz/DistanceMap'));

export default function ThreatIntelligence() {
  const [threatData, setThreatData] = useState(null);
  const [novelAlerts, setNovelAlerts] = useState([]);
  const [novelOnly, setNovelOnly] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [distanceOpened, setDistanceOpened] = useState(false);
  const [copiedEvent, setCopiedEvent] = useState('');
  const rootRef = useRef(null);

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

  useGSAP(() => {
    const root = rootRef.current;
    if (!root || loading || activeTab !== 'overview') return undefined;
    return createMotionScope(root, (reduced) => {
      if (!rootRef.current) return;
      const items = gsap.utils.toArray('[data-threat-entrance]', root);
      if (!items.length) return;
      gsap.fromTo(items, { autoAlpha: 0, y: reduced ? 0 : 12 }, {
        autoAlpha: 1,
        y: 0,
        duration: reduced ? 0.18 : 0.48,
        stagger: reduced ? 0 : 0.055,
        ease: motion.ease,
        clearProps: 'opacity,transform,visibility',
      });
    });
  }, { scope: rootRef, dependencies: [activeTab, loading, Boolean(threatData), Boolean(loadError)], revertOnUpdate: true });

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
  const integerValue = (value) => value == null || !Number.isFinite(Number(value)) ? '—' : Number(value).toFixed(0);

  return (
    <div ref={rootRef} className="mx-auto w-full max-w-[1400px] space-y-5">
      <header data-threat-entrance className="px-1 pb-1">
        <h1 className="font-[family-name:var(--soc-font-display)] text-[38px] font-light leading-tight tracking-tight text-slate-50">Threat Intelligence</h1>
        <p className="mt-1 text-sm text-slate-400">Known threat families and open-set detections</p>
      </header>
      <div role="tablist" aria-label="Threat intelligence views" onKeyDown={(event) => {
        if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
        event.preventDefault();
        const tabs = ['overview', 'mitre', 'distance'];
        const currentIndex = Math.max(0, tabs.indexOf(activeTab));
        const nextTab = tabs[(currentIndex + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
        if (nextTab === 'distance') setDistanceOpened(true);
        setActiveTab(nextTab);
        event.currentTarget.querySelector(`[data-view-tab="${nextTab}"]`)?.focus();
      }} className="relative flex w-full max-w-xl border-b border-white/[0.08]">
        <span aria-hidden="true" className={`pointer-events-none absolute bottom-0 left-0 h-0.5 w-1/3 bg-gradient-to-r from-blue-400 to-violet-400 transition-transform duration-200 ease-out ${activeTab === 'mitre' ? 'translate-x-full' : activeTab === 'distance' ? 'translate-x-[200%]' : ''}`} />
        <button type="button" id="threat-overview-tab" role="tab" aria-controls="threat-overview-panel" data-view-tab="overview" aria-selected={activeTab === 'overview'} tabIndex={activeTab === 'overview' ? 0 : -1} onClick={() => setActiveTab('overview')} className={`flex-1 rounded-t-xl px-3 py-3 text-sm font-normal transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-300 ${activeTab === 'overview' ? 'text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}>Threat intelligence</button>
        <button type="button" id="threat-mitre-tab" role="tab" aria-controls="threat-mitre-panel" data-view-tab="mitre" aria-selected={activeTab === 'mitre'} tabIndex={activeTab === 'mitre' ? 0 : -1} onClick={() => setActiveTab('mitre')} className={`flex-1 rounded-t-xl px-3 py-3 text-sm font-normal transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-300 ${activeTab === 'mitre' ? 'text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}>MITRE ATT&amp;CK</button>
        <button type="button" id="threat-distance-tab" role="tab" aria-controls="threat-distance-panel" data-view-tab="distance" aria-selected={activeTab === 'distance'} tabIndex={activeTab === 'distance' ? 0 : -1} onClick={() => { setDistanceOpened(true); setActiveTab('distance'); }} className={`flex-1 rounded-t-xl px-3 py-3 text-sm font-normal transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-300 ${activeTab === 'distance' ? 'text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}>Distance map</button>
      </div>
      {activeTab === 'mitre' && <div id="threat-mitre-panel" role="tabpanel" aria-labelledby="threat-mitre-tab"><Suspense fallback={<div aria-busy="true" className="space-y-3 rounded-2xl border border-white/[0.08] bg-[var(--soc-raised)] p-5"><Skeleton className="h-4 w-44" /><Skeleton className="h-24" /></div>}><MitreMatrix /></Suspense></div>}
      {distanceOpened && <div id="threat-distance-panel" role="tabpanel" aria-labelledby="threat-distance-tab" hidden={activeTab !== 'distance'}><Suspense fallback={<div aria-busy="true" className="space-y-3 rounded-2xl border border-white/[0.08] bg-[var(--soc-raised)] p-5"><Skeleton className="h-4 w-44" /><Skeleton className="h-72" /></div>}><DistanceMap /></Suspense></div>}
      {activeTab === 'overview' && (loading && !threatData ? <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab" aria-busy="true" className="grid gap-5"><Skeleton className="h-48 rounded-2xl" /><div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((item) => <Skeleton key={item} className="h-32 rounded-2xl" />)}</div><Skeleton className="h-72 rounded-2xl" /></div>
        : loadError && !threatData ? <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab"><EmptyState icon={ShieldAlert} title="Threat intelligence data is unavailable" description="Threat intelligence could not be loaded. Please try again later." className="bg-[var(--soc-raised)]" /></div>
          : <div id="threat-overview-panel" role="tabpanel" aria-labelledby="threat-overview-tab" className="space-y-6">
            <section data-threat-entrance className="relative overflow-hidden rounded-2xl border border-purple-400/25 bg-[radial-gradient(ellipse_at_top_right,rgba(168,85,247,0.13),transparent_56%),var(--soc-raised)] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div><p className="text-[13px] font-normal text-purple-200">Open-set triage</p><h2 className="mt-1 text-xl font-medium text-slate-100">Unknown / Novel Threat View</h2><p className="mt-1 text-sm text-slate-400">Review behavior that falls outside known-class confidence or centroid boundaries.</p></div>
                <Toggle checked={novelOnly} onChange={setNovelOnly} label="UNKNOWN_NOVEL only" className="rounded-full border border-white/[0.08] bg-black/15 px-3.5 py-2.5 text-sm text-slate-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple-300" />
              </div>
              <div className="mt-4 rounded-2xl border border-purple-400/20 bg-purple-400/[0.045] p-3.5 text-sm font-medium text-purple-100">Novel / Unfamiliar Behavior — Requires Analyst Triage</div>
              <div className="mt-3 grid gap-2">
                {visibleNovel.map((item, index) => {
                  const distance = item.centroid_distance ?? item.open_set_distance;
                  const novelty = item.novelty_score ?? item.details?.open_set_score;
                  const eventId = item.event_id;
                  const score = novelty == null || !Number.isFinite(Number(novelty)) ? null : Number(novelty);
                  const distanceValue = distance == null || !Number.isFinite(Number(distance)) ? null : Number(distance);
                  const eventIdText = eventId == null ? '' : String(eventId);
                  const timestampValue = item.timestamp || item.created_at;
                  const timestamp = timestampValue ? new Date(timestampValue) : null;
                  const validTimestamp = timestamp && Number.isFinite(timestamp.getTime());
                  return <article key={item.detection_id || eventIdText || `${timestampValue || 'novel'}-${index}`} className="relative overflow-hidden rounded-[20px] border border-purple-300/15 bg-gradient-to-b from-purple-400/[0.045] to-white/[0.015] p-4 transition-colors duration-200 hover:border-purple-300/30 hover:bg-purple-400/[0.07] sm:p-5">
                    <span aria-hidden="true" className="absolute inset-y-3 left-0 w-[2px] rounded-full bg-purple-300/75" />
                    <div className="flex flex-wrap items-start justify-between gap-3 pl-2"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Badge tone="UNKNOWN_NOVEL">{String(item.verdict || 'UNKNOWN_NOVEL')}</Badge>{eventIdText && <><span className="break-all font-mono text-[13px] tabular-nums text-slate-300">{eventIdText}</span><button type="button" aria-label={`Copy event ID ${eventIdText}`} onClick={() => copyEvent(eventIdText)} className="rounded-full border border-white/[0.08] bg-white/[0.025] p-1.5 text-slate-400 transition hover:bg-white/[0.07] hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple-300"><Copy className="h-3.5 w-3.5" /></button></>}{copiedEvent === eventIdText && <span className="text-[13px] text-emerald-300">Copied</span>}</div><p className={`mt-2 text-sm ${validTimestamp ? 'text-slate-400' : 'text-slate-500'}`}>{validTimestamp ? timestamp.toLocaleString() : 'Timestamp unavailable'}</p></div>
                      <div className="flex flex-wrap gap-2"><span className="rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[13px] text-slate-300">Centroid distance <strong className={`ml-1 font-mono tabular-nums ${distanceValue == null ? 'text-slate-500' : 'text-amber-200'}`}>{distanceValue == null ? '—' : distanceValue.toFixed(4)}</strong></span></div></div>
                    <div className="mt-3 max-w-xl pl-2"><div className="mb-1.5 flex items-center justify-between text-[13px]"><span className="text-slate-400">Novelty score</span><strong className={`font-mono tabular-nums ${score == null ? 'text-slate-500' : 'text-purple-200'}`}>{score == null ? '—' : score.toFixed(3)}</strong></div><div className="h-2 overflow-hidden rounded-full bg-white/[0.07]"><div className="h-full rounded-full bg-gradient-to-r from-purple-500 to-violet-300" style={{ width: `${score == null ? 0 : Math.max(0, Math.min(1, score)) * 100}%` }} /></div></div>
                  </article>;
                })}
                {visibleNovel.length === 0 && <p className="py-3 text-xs text-slate-400">No UNKNOWN_NOVEL detections are currently recorded.</p>}
              </div>
            </section>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div data-threat-entrance><StatCard label="Total Detections" value={summary?.total_detections ?? null} formatValue={integerValue} className="border-t-2 border-t-blue-400/50" /></div>
              <div data-threat-entrance><StatCard label="Known Attacks (Supervised)" value={summary?.known_threats_count ?? null} formatValue={integerValue} className="border-t-2 border-t-amber-400/50" /></div>
              <div data-threat-entrance><StatCard label="Unknown Candidates" value={summary?.unknown_candidates_count ?? null} formatValue={integerValue} className="border-t-2 border-t-purple-400/50" /></div>
              <div data-threat-entrance><StatCard label="Candidate Rate" value={candidateRate == null ? null : Number(candidateRate) * 100} formatValue={(value) => value == null || !Number.isFinite(Number(value)) ? '—' : `${Number(value).toFixed(1)}%`} detail={<div className="h-1.5 w-20 overflow-hidden rounded-full bg-white/[0.07]" role="progressbar" aria-label="Candidate Rate" aria-valuemin="0" aria-valuemax="100" aria-valuenow={candidateRate == null || !Number.isFinite(Number(candidateRate)) ? undefined : Math.max(0, Math.min(100, Number(candidateRate) * 100))}><div className="h-full rounded-full bg-emerald-400" style={{ width: `${candidateRate == null || !Number.isFinite(Number(candidateRate)) ? 0 : Math.max(0, Math.min(1, Number(candidateRate))) * 100}%` }} /></div>} className="border-t-2 border-t-emerald-400/50" /></div>
            </div>

            <div className="grid gap-5 lg:grid-cols-2">
              <Card data-threat-entrance className="p-5 sm:p-6">
                <div className="mb-4 flex items-center gap-3"><div className="rounded-2xl border border-amber-400/15 bg-amber-400/10 p-2.5 text-amber-200"><ShieldAlert className="h-5 w-5" /></div><div><h3 className="text-base font-medium text-slate-100">Classified Known Attack Families</h3><p className="text-sm text-slate-400">CICIDS2017 LightGBM classifier</p></div></div>
                <div className="space-y-2">{(known_categories || []).map((cat, idx) => <div key={String(cat) || idx} className="flex items-center justify-between gap-3 rounded-2xl border border-white/[0.06] bg-white/[0.02] p-3.5 transition-colors duration-200 hover:border-white/[0.12] hover:bg-white/[0.05]"><div className="min-w-0"><p className="text-sm font-medium text-slate-200">{String(cat)}</p><p className="mt-1 text-sm text-slate-400">Model class exceeded its configured logit-margin threshold</p></div><Badge tone="medium">CLASSIFIED</Badge></div>)}{(known_categories || []).length === 0 && <EmptyState icon={CheckCircle2} title="No known attack families" description="No classified attack families are present in the current threat data." />}</div>
              </Card>
              <Card data-threat-entrance className="p-5 sm:p-6">
                <div className="mb-4 flex items-center gap-3"><div className="rounded-2xl border border-purple-400/15 bg-purple-400/10 p-2.5 text-purple-200"><AlertTriangle className="h-5 w-5" /></div><div><h3 className="text-base font-medium text-slate-100">Unconfirmed Candidate Queue</h3><p className="text-sm text-slate-400">Flows rejected by the known-validation score threshold; candidates need analyst review</p></div></div>
                <div className="space-y-2">{(threatData?.unknown_candidates || []).slice(0, 4).map((th, idx) => { const distance = th.open_set_distance == null || !Number.isFinite(Number(th.open_set_distance)) ? null : Number(th.open_set_distance); const reconstructionError = th.reconstruction_error == null || !Number.isFinite(Number(th.reconstruction_error)) ? null : Number(th.reconstruction_error); const candidateTimestamp = th.timestamp ? new Date(th.timestamp) : null; const validCandidateTimestamp = candidateTimestamp && Number.isFinite(candidateTimestamp.getTime()); return <div key={th.detection_id || th.event_id || `${th.timestamp || 'candidate'}-${idx}`} className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-white/[0.06] bg-white/[0.02] p-3.5 transition-colors duration-200 hover:border-purple-300/20 hover:bg-white/[0.05]"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><Badge tone="UNKNOWN_NOVEL">Unconfirmed candidate</Badge><span className="font-mono text-[13px] tabular-nums text-slate-400">#{String(th.event_id || '').slice(-6) || '—'}</span></div><p className="mt-1.5 text-sm text-slate-400">Latent Distance: <span className={`font-mono font-medium tabular-nums ${distance == null ? 'text-slate-500' : 'text-purple-200'}`}>{distance == null ? '—' : distance.toFixed(2)}</span></p></div><div className="text-left sm:text-right"><span className={`font-mono text-sm tabular-nums ${reconstructionError == null ? 'text-slate-500' : 'text-slate-300'}`}>Recon Err: {reconstructionError == null ? '-' : reconstructionError.toFixed(3)}</span><p className={`mt-1 text-sm ${validCandidateTimestamp ? 'text-slate-400' : 'text-slate-500'}`}>{validCandidateTimestamp ? candidateTimestamp.toLocaleTimeString() : 'Timestamp unavailable'}</p></div></div>; })}{(threatData?.unknown_candidates || []).length === 0 && <EmptyState icon={AlertTriangle} title="No unconfirmed candidates" description="No candidate flows are currently recorded in this queue." />}</div>
              </Card>
            </div>
          </div>)}
    </div>
  );
}
