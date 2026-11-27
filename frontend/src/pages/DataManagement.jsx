import React, { useState, useEffect, useCallback } from 'react';
import {
  Upload, Database, CheckCircle2, Activity,
  AlertCircle, Loader2, FlaskConical, BarChart2, ChevronDown, ChevronUp, Play
} from '../lib/icons';
import { api } from '../services/api';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';

// ─── Helper: format percentage ─────────────────────────────────────────────
const pct = (v) => (v != null ? (v * 100).toFixed(2) + '%' : '—');
const f4  = (v) => (v != null ? v.toFixed(4) : '—');

// ─── Collapsible section ───────────────────────────────────────────────────
function Collapsible({ title, badge, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = `panel-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-white/70 shadow-[inset_0_1px_0_rgba(255,255,255,0.025)]">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center justify-between bg-white/[0.015] p-4 text-left transition-colors hover:bg-white/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-400"
      >
        <span className="text-xs font-bold text-slate-200 flex items-center gap-2">
          {title}
          {badge && (
            <span className="rounded-full border border-blue-300/15 bg-blue-400/[0.06] px-2 py-0.5 font-mono text-xs tabular-nums text-blue-200">
              {badge}
            </span>
          )}
        </span>
        <ChevronDown className={`h-4 w-4 text-slate-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>
      <div id={panelId} aria-hidden={!open} inert={!open} className={`grid transition-[grid-template-rows] duration-300 ease-out ${open ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
        <div className="min-h-0 overflow-hidden">
          <div className="border-t border-white/[0.06] bg-[var(--chip)] p-4">{children}</div>
        </div>
      </div>
    </div>
  );
}

function MetricCell({ value, format = f4, className = '' }) {
  const numeric = Number(value);
  const hasValue = value != null && Number.isFinite(numeric);
  const width = hasValue ? Math.max(0, Math.min(100, numeric * 100)) : 0;
  return (
    <td className={`relative overflow-hidden text-right font-mono tabular-nums ${className}`}>
      {hasValue && <span aria-hidden="true" className="pointer-events-none absolute inset-y-1 right-1 rounded-sm bg-blue-400/[0.07]" style={{ width: `${width}%` }} />}
      <span className="relative">{format(value)}</span>
    </td>
  );
}

// ─── Known-Classifier results panel ───────────────────────────────────────
function KnownClassifierPanel({ data }) {
  if (!data || (![data.LightGBM, data.XGBoost].some((model) => model && (
    model.macro_f1 != null || model.accuracy != null || (Array.isArray(model.class_names) && model.class_names.length > 0)
  )))) return (
    <div className="rounded-xl border border-dashed border-white/10 bg-[var(--chip)] p-6 text-center">
      <Database className="mx-auto mb-2 h-6 w-6 text-slate-500" />
      <p className="text-sm font-medium text-slate-200">Known-class metrics are unavailable in these results.</p>
      <p className="mt-1 text-xs text-slate-400">This section expects LightGBM and XGBoost class names, per-class precision, recall, F1 and support, plus macro-F1 and accuracy.</p>
    </div>
  );
  const { LightGBM, XGBoost, date, data_hash, excluded_labels } = data;

  const ModelTable = ({ model, name }) => (
    <div className="mb-4">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-xs font-bold text-slate-200">{name}</span>
        <span className="font-mono text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
          Macro-F1: {f4(model?.macro_f1)}
        </span>
        <span className="font-mono text-xs text-slate-400">Accuracy: {pct(model?.accuracy)}</span>
      </div>
      <div className="max-h-[28rem] overflow-auto rounded-lg">
        <table className="w-full text-xs text-slate-300">
          <thead className="sticky top-0 z-[1] bg-white">
            <tr className="border-b border-white/[0.08] text-slate-400">
              <th className="text-left pb-1 pr-4">Class</th>
              <th className="text-right pb-1 pr-4">Precision</th>
              <th className="text-right pb-1 pr-4">Recall</th>
              <th className="text-right pb-1 pr-4">F1</th>
              <th className="text-right pb-1">Support</th>
            </tr>
          </thead>
          <tbody>
            {model?.class_names?.map(cls => {
              const r = model.per_class?.[cls];
              return (
                <tr key={cls} className="border-b border-white/[0.04] transition-colors hover:bg-white/[0.035]">
                  <td className="py-2 pr-4 font-mono text-blue-200">{cls}</td>
                  <MetricCell value={r?.precision} className="pr-4" />
                  <MetricCell value={r?.recall} className="pr-4" />
                  <MetricCell value={r?.f1} className="pr-4 font-semibold" />
                  <td className="text-right font-mono tabular-nums text-slate-300">{r?.support?.toLocaleString()}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 text-xs font-mono text-slate-500">
        <span>date: {date?.slice(0, 16).replace('T', ' ')} UTC</span>
        <span>data_hash: {data_hash}</span>
        <span className="text-amber-400">excluded: {excluded_labels?.join(', ')}</span>
      </div>
      <ModelTable model={LightGBM} name="LightGBM" />
      <ModelTable model={XGBoost}  name="XGBoost" />
    </div>
  );
}

// ─── Open-Set results panel ────────────────────────────────────────────────
const DETECTOR_LABELS = {
  confidence:       'Confidence (1–max_prob)',
  isolation_forest: 'Isolation Forest',
  autoencoder:      'Denoising Autoencoder',
  mahalanobis:      'Mahalanobis Distance',
};

function OpenSetPanel({ data }) {
  if (!data) return null;
  const { per_family, macro_average, warnings, threshold_percentile, date, data_hash } = data;
  const detectorNames = ['confidence', 'isolation_forest', 'autoencoder', 'mahalanobis'];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 text-xs font-mono text-slate-500">
        <span>date: {date?.slice(0, 16).replace('T', ' ')} UTC</span>
        <span>data_hash: {data_hash}</span>
        <span className="text-blue-400">threshold: {threshold_percentile}th pct of known-val scores</span>
      </div>

      {/* Macro-average summary */}
      <div>
        <p className="text-xs font-bold text-slate-300 mb-2">Macro-Average Across All Families</p>
        <div className="max-h-[28rem] overflow-auto rounded-lg">
          <table className="w-full text-xs text-slate-300">
            <thead className="sticky top-0 z-[1] bg-white">
              <tr className="border-b border-white/[0.08] text-slate-400">
                <th className="text-left pb-1 pr-4">Detector</th>
                <th className="text-right pb-1 pr-4">AUROC ↑</th>
                <th className="text-right pb-1 pr-4">FPR@95% ↓</th>
                <th className="text-right pb-1 pr-4">Unk Rejection ↑</th>
                <th className="text-right pb-1">Known FalseReject ↓</th>
              </tr>
            </thead>
            <tbody>
              {detectorNames.map(det => {
                const m = macro_average?.[det];
                return (
                <tr key={det} className="border-b border-white/[0.04] transition-colors hover:bg-white/[0.035]">
                    <td className="py-2 pr-4 font-mono text-blue-200">{DETECTOR_LABELS[det]}</td>
                    <MetricCell value={m?.AUROC} className="pr-4 font-semibold" />
                    <MetricCell value={m?.FPR_at_95pct_TPR} className="pr-4" />
                    <MetricCell value={m?.unknown_rejection_rate} format={pct} className="pr-4" />
                    <MetricCell value={m?.known_false_reject_rate} format={pct} />
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Per-family results */}
      {per_family?.map(fam => (
        <Collapsible
          key={fam.family}
          title={`Family: ${fam.family}`}
          badge={`${fam.n_test_unknown?.toLocaleString()} unknown test samples`}
        >
          {fam.skipped ? (
            <p className="text-xs text-amber-400">{fam.skipped}</p>
          ) : (
            <div className="max-h-[28rem] overflow-auto rounded-lg">
              <table className="w-full text-xs text-slate-300">
                <thead className="sticky top-0 z-[1] bg-white">
                  <tr className="border-b border-white/[0.08] text-slate-400">
                    <th className="text-left pb-1 pr-4">Detector</th>
                    <th className="text-right pb-1 pr-4">AUROC ↑</th>
                    <th className="text-right pb-1 pr-4">FPR@95% ↓</th>
                    <th className="text-right pb-1 pr-4">Unk Rejection ↑</th>
                    <th className="text-right pb-1">Known FR ↓</th>
                    <th className="text-right pb-1 pl-4">Threshold</th>
                  </tr>
                </thead>
                <tbody>
                  {detectorNames.map(det => {
                    const d = fam.detectors?.[det];
                    if (!d) return null;
                    const weak = d.AUROC < 0.60;
                      return (
                      <tr key={det} className="border-b border-white/[0.04] transition-colors hover:bg-white/[0.035]">
                        <td className="py-2 pr-4 font-mono text-blue-200">
                          {DETECTOR_LABELS[det]}
                          {weak && <span className="ml-2 text-xs text-amber-300">⚠ weak</span>}
                        </td>
                        <MetricCell value={d.AUROC} className="pr-4 font-semibold" />
                        <MetricCell value={d.FPR_at_95pct_TPR} className="pr-4" />
                        <MetricCell value={d.unknown_rejection_rate} format={pct} className="pr-4" />
                        <MetricCell value={d.known_false_reject_rate} format={pct} />
                        <MetricCell value={d.threshold_value} className="pl-4 text-slate-300" />
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Collapsible>
      ))}

      {/* Warnings */}
      {warnings?.length > 0 && (
        <div className="rounded-xl border border-amber-300/20 bg-gradient-to-r from-amber-500/[0.10] to-amber-400/[0.035] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.025)]">
          <p className="mb-2 text-sm font-semibold text-amber-200">⚠️ Weak / Suspicious Results</p>
          {warnings.map((w, i) => (
            <p key={i} className="mb-1 text-xs leading-relaxed text-amber-100/90">{w}</p>
          ))}
        </div>
      )}
    </div>
  );
}


// ─── Main page ─────────────────────────────────────────────────────────────
export default function DataManagement({ role = 'viewer' }) {
  const canAnalyze = role === 'analyst' || role === 'admin';
  const isAdmin = role === 'admin';
  const [dragOver, setDragOver] = useState(false);
  const pageRef = React.useRef(null);
  const [modelStatus,    setModelStatus]    = useState(null);
  const [uploadStatus,   setUploadStatus]   = useState(null);
  const [isUploading,    setIsUploading]    = useState(false);

  const [cicidsInfo,     setCicidsInfo]     = useState(null);
  const [evalResults,    setEvalResults]    = useState(null);
  const [evalRunning,    setEvalRunning]    = useState(false);
  const [evalError,      setEvalError]      = useState(null);
  const [demoLoading,    setDemoLoading]    = useState(false);
  const [demoMessage,    setDemoMessage]    = useState(null);
  const [replayStatus,   setReplayStatus]   = useState(null);
  const [replayN,        setReplayN]        = useState(3000);
  const [replaySpeed,    setReplaySpeed]    = useState(10);
  const [replayError,    setReplayError]    = useState(null);

  useGSAP(() => createMotionScope(pageRef.current, (reduced) => {
    const cards = pageRef.current?.querySelectorAll('[data-page-card]');
    if (!cards?.length) return;
    gsap.fromTo(cards, { opacity: 0, y: reduced ? 0 : 14 }, {
      opacity: 1, y: 0, duration: reduced ? 0.2 : motion.duration.entrance,
      stagger: reduced ? 0 : motion.stagger, ease: motion.ease, clearProps: 'opacity,transform',
    });
  }), { scope: pageRef, revertOnUpdate: true });

  const fetchStatus = useCallback(async () => {
    try {
      const [data, cicids, evalRes] = await Promise.all([
        api.getModelsStatus(),
        api.getCicidsStatus().catch(() => null),
        api.getEvaluationResults().catch(() => null),
      ]);
      setModelStatus(data);
      setCicidsInfo(cicids);
      if (evalRes?.available) setEvalResults(evalRes);
    } catch (err) {
      console.error(err);
    }
  }, []);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  useEffect(() => {
    let mounted = true;
    const poll = () => api.getDemoReplayStatus().then((status) => mounted && setReplayStatus(status)).catch(() => {});
    poll();
    const timer = setInterval(poll, 2000);
    return () => { mounted = false; clearInterval(timer); };
  }, []);

  const startReplay = async () => {
    setReplayError(null);
    try { await api.startDemoReplay(Number(replayN), Number(replaySpeed)); }
    catch (error) { setReplayError(error.message); }
  };

  const stopReplay = async () => {
    try { setReplayStatus(await api.stopDemoReplay()); }
    catch (error) { setReplayError(error.message); }
  };

  const handleRunEvaluation = async () => {
    setEvalRunning(true);
    setEvalError(null);
    try {
      const { job_id: jobId } = await api.triggerEvaluationRun();
      while (true) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        const status = await api.getEvaluationStatus(jobId);
        if (status.status === 'failed') throw new Error(status.error || 'Evaluation failed');
        if (status.status === 'done') break;
      }
      await fetchStatus();
    } catch (err) {
      setEvalError(err.message || 'Failed to start evaluation run');
    } finally {
      setEvalRunning(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsUploading(true);
    setUploadStatus(null);
    try {
      let result = await api.uploadLogs(file);
      if (result.status === 'queued' && result.job_id) {
        const uploadJobId = result.job_id;
        setUploadStatus({ success: true, pending: true, message: `Upload queued · ${result.progress?.total_rows ?? 'Many'} rows` });
        while (result.status === 'queued' || result.status === 'running') {
          await new Promise((resolve) => setTimeout(resolve, 1000));
          result = await api.getUploadStatus(uploadJobId);
          const progress = result.progress || {};
          setUploadStatus({
            success: result.status !== 'failed',
            pending: result.status === 'queued' || result.status === 'running',
            message: result.status === 'failed'
              ? (result.error || 'Upload failed')
              : result.status === 'completed'
                ? (result.result?.message || 'Upload completed.')
                : `Ingesting ${progress.rows_read ?? 0} of ${progress.total_rows ?? '—'} rows…`,
          });
        }
        if (result.status === 'failed') throw new Error(result.error || 'Upload failed');
      } else {
        setUploadStatus({ success: true, message: result.message });
      }
    } catch (err) {
      setUploadStatus({ success: false, message: err.message || 'Upload failed' });
    } finally {
      setIsUploading(false);
    }
  };

  const handleLoadDemo = async () => {
    setDemoLoading(true);
    setDemoMessage(null);
    try {
      const result = await api.loadDemoScenarios();
      setDemoMessage(result.message);
      window.dispatchEvent(new Event('synthetic-demo-updated'));
    } catch (err) {
      setDemoMessage(err.message || 'Failed to load synthetic demo data.');
    } finally {
      setDemoLoading(false);
    }
  };

  return (
    <div ref={pageRef} className="mx-auto max-w-[1600px] space-y-6">
      {/* Header */}
      <div data-page-card className="soc-card flex flex-wrap items-center justify-between gap-4 rounded-[var(--r-card)] p-6">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-blue-200/80">Platform · Data &amp; models</p>
          <h1 className="flex items-center gap-2 font-display text-3xl font-bold leading-tight tracking-tight text-[var(--ink)]">
            <Database aria-hidden="true" className="h-5 w-5 text-[var(--cobalt)]" /> Data Ingestion &amp; Model Governance
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Upload telemetry, run CICIDS2017 evaluation pipeline, inspect rigorous multi-class + open-set metrics
          </p>
        </div>
        <div className="flex max-w-full flex-wrap items-center gap-2">
          <span className="rounded-full border border-emerald-300/15 bg-emerald-400/[0.07] px-3 py-1.5 text-xs font-semibold text-emerald-200">ALL 8 CSVs MOUNTED</span>
          {(evalResults?.files || []).map((file) => <span key={file} className="max-w-full truncate rounded-lg border border-white/[0.08] bg-[var(--chip)] px-2.5 py-1.5 font-mono text-xs tabular-nums text-slate-300">{file}</span>)}
        </div>
      </div>

      {/* CICIDS2017 Evaluation Runner */}
      <div data-page-card className="rounded-2xl border border-blue-300/15 bg-white p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.035)]">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400">
              <FlaskConical className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h4 className="text-sm font-bold text-slate-100">
                  CICIDS2017 — Rigorous Multi-Class + Open-Set Evaluation
                </h4>
                <span className="rounded-full border border-emerald-300/15 bg-emerald-400/[0.07] px-2.5 py-1 font-mono text-xs font-semibold tabular-nums text-emerald-200">
                  ALL 8 CSVs MOUNTED
                </span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">
                Leave-one-family-out · 4 detectors · 5 attack families · thresholds from known-val only
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={fetchStatus}
              className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.035] px-4 py-2 text-xs font-semibold text-slate-200 transition-colors hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
            >
              <Activity className="w-4 h-4" /> Reload Results
            </button>
            {isAdmin && (
              <button
                onClick={handleRunEvaluation}
                disabled={evalRunning}
                className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2 text-xs font-semibold text-white shadow-[0_8px_24px_rgba(59,130,246,0.18)] transition-transform hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 disabled:opacity-50"
              >
                {evalRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                <span>{evalRunning ? 'Evaluation running...' : 'Run Full Evaluation (5–30 min)'}</span>
              </button>
            )}
          </div>
        </div>

        {evalError && (
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2 mb-4">
            <AlertCircle className="w-4 h-4" /> {evalError}
          </div>
        )}

        {evalRunning && <div className="mb-4 rounded-xl border border-blue-300/15 bg-blue-400/[0.045] p-3" role="status" aria-label="Evaluation running">
          <div className="mb-2 flex items-center justify-between text-xs"><span className="font-medium text-blue-100">Evaluation running</span><span className="font-mono tabular-nums text-slate-400">Status checks every 2 seconds</span></div>
          <div className="h-1 overflow-hidden rounded-full bg-white/[0.07]"><div className="h-full w-full origin-left animate-pulse bg-gradient-to-r from-blue-400/50 via-violet-400 to-blue-400/50" /></div>
        </div>}

        {!evalResults?.available ? (
          <div className="p-6 rounded-xl bg-white border border-dashed border-[var(--line)] text-center">
            <BarChart2 className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="text-xs text-slate-400">No evaluation results yet.</p>
              <p className="text-xs text-slate-500 mt-1">
              {isAdmin ? <>Click <strong>"Run Full Evaluation"</strong> above, or run:<br />
              <code className="font-mono text-blue-400">python backend/ml/run_cicids_eval.py</code>
              </> : 'Evaluation results are available to your role when runs have been saved.'}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Files */}
            <div className="flex flex-wrap gap-2">
              {evalResults.files?.map(f => (
                <span key={f} className="font-mono text-xs px-2 py-1 rounded bg-white border border-[var(--line)] text-slate-400">
                  {f}
                </span>
              ))}
            </div>

            {/* Known classifier */}
            <Collapsible title="Known-Class Classifier Results" badge="LightGBM + XGBoost" defaultOpen>
              <KnownClassifierPanel data={evalResults.known_classifier} />
            </Collapsible>

            {/* Open-set */}
            <Collapsible title="Open-Set Evaluation Results" badge="4 detectors × 5 families" defaultOpen>
              <OpenSetPanel data={evalResults.open_set} />
            </Collapsible>
          </div>
        )}
      </div>

      {/* File Upload */}
      <div className="grid grid-cols-1 gap-6">
        <div data-page-card className="rounded-2xl border border-white/[0.08] bg-white p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h4 className="text-sm font-bold text-slate-200">Held-out CICIDS replay</h4>
              <p className="text-xs text-slate-500 mt-1">Streams prepared rows through the live detector and WebSocket.</p>
              <p className="mt-2 font-mono text-xs tabular-nums text-blue-100">{replayStatus?.status || 'idle'} · {replayStatus?.processed || 0} / {replayStatus?.total || 0} rows</p>
              {['queued', 'running', 'stopping'].includes(replayStatus?.status) && <div className="mt-2 h-1.5 w-full max-w-sm overflow-hidden rounded-full bg-white/[0.07]" role="progressbar" aria-label="Replay progress" aria-valuemin="0" aria-valuemax={replayStatus?.total || 0} aria-valuenow={replayStatus?.processed || 0}>
                <div className="h-full w-full origin-left rounded-full bg-gradient-to-r from-blue-500 to-violet-400 transition-transform duration-500" style={{ transform: `scaleX(${replayStatus?.total > 0 ? Math.min(1, Math.max(0, replayStatus.processed / replayStatus.total)) : 0})` }} />
              </div>}
              {replayError && <p className="text-xs text-rose-300 mt-2">{replayError}</p>}
              {replayStatus?.error && <p className="text-xs text-rose-300 mt-2">{replayStatus.error}</p>}
            </div>
            {isAdmin && <div className="flex flex-wrap items-end gap-2 rounded-xl border border-white/[0.06] bg-[var(--chip)] p-3">
              <label className="text-xs text-slate-300">Rows<input type="number" min="1" value={replayN} onChange={(e) => setReplayN(e.target.value)} className="mt-1 block w-24 rounded-lg border border-white/10 bg-white px-2 py-2 font-mono text-xs tabular-nums text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400" /></label>
              <label className="text-xs text-slate-300">Rows / sec<input type="number" min="0" value={replaySpeed} onChange={(e) => setReplaySpeed(e.target.value)} className="mt-1 block w-24 rounded-lg border border-white/10 bg-white px-2 py-2 font-mono text-xs tabular-nums text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400" /></label>
              <button type="button" onClick={startReplay} disabled={['queued', 'running', 'stopping'].includes(replayStatus?.status)} className="rounded-xl bg-blue-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-blue-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 disabled:opacity-40">Start replay</button>
              <button type="button" onClick={stopReplay} disabled={!['queued', 'running'].includes(replayStatus?.status)} className="rounded-xl border border-rose-300/20 bg-rose-500/10 px-4 py-2 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-300 disabled:opacity-40">Stop replay</button>
            </div>}
          </div>
        </div>
        <div data-page-card className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-amber-300/15 bg-white p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.025)]">
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-bold text-slate-200">Synthetic correlation scenarios</h4>
              <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-bold tracking-wide text-amber-200">DEMO</span>
            </div>
            <p className="text-xs text-slate-500 mt-1">Loads labelled events only. Run correlation separately from Incident Management.</p>
            <div className="mt-2 flex flex-wrap gap-1.5" aria-label="Four built-in demo scenarios">
              {['multi_stage_takeover', 'brute_force_only', 'benign_admin', 'normal_employee_day'].map((scenario) => (
                <span key={scenario} className="rounded-full border border-amber-500/20 bg-white px-2 py-1 text-xs text-amber-100">{scenario.replaceAll('_', ' ')}</span>
              ))}
            </div>
            {demoMessage && <p className="text-xs text-amber-200 mt-2">{demoMessage}</p>}
          </div>
          {isAdmin && <button
            onClick={handleLoadDemo}
            disabled={demoLoading}
            className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-2"
          >
            {demoLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FlaskConical className="w-4 h-4" />}
            {demoLoading ? 'Loading demo events…' : 'Load demo events'}
          </button>}
        </div>
        {/* Upload */}
        <div data-page-card className="rounded-2xl border border-white/[0.08] bg-white p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Security Telemetry Upload</h4>
              <p className="text-xs text-slate-500">Supports CSV &amp; JSON (Auth, Sysmon, Network flows)</p>
            </div>
          </div>
          {canAnalyze ? <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFileUpload({ target: { files: e.dataTransfer.files } }); }}
            className={`rounded-2xl border-2 border-dashed p-8 text-center transition-colors ${dragOver ? 'border-blue-300 bg-blue-400/[0.09]' : 'border-white/10 bg-[var(--chip)] hover:border-blue-300/40'}`}
          >
            <input type="file" id="file-upload" accept=".csv,.json" onChange={handleFileUpload} className="hidden" />
            <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center">
              <Upload className="w-8 h-8 text-slate-500 mb-2" />
              <span className="text-xs font-bold text-slate-200">Click to upload security logs</span>
              <span className="text-xs text-slate-500 mt-1">.CSV or .JSON format</span>
            </label>
          </div> : <p className="text-xs text-slate-500">Telemetry upload is available to analysts and admins.</p>}
          {isUploading && (
            <div className="flex items-center gap-2 text-xs text-blue-400 mt-3">
              <Loader2 className="w-4 h-4 animate-spin" /> Ingesting and normalizing...
            </div>
          )}
          {uploadStatus && (
            <div className={`p-3 rounded-xl mt-3 text-xs flex items-center gap-2 ${
              uploadStatus.success
                ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
                : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
            }`}>
              {uploadStatus.pending ? <Loader2 className="w-4 h-4 animate-spin" /> : uploadStatus.success ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
              <span>{uploadStatus.message}</span>
            </div>
          )}
        </div>

      </div>

      {/* Model Weights Grid */}
        <div data-page-card className="rounded-2xl border border-white/[0.08] bg-white p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
        <h4 className="text-sm font-bold text-slate-200 mb-4">ML Model Weights &amp; Governance</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {Object.entries(modelStatus?.models || {}).map(([key, m]) => (
            <div key={key} className="p-4 rounded-xl bg-white border border-[var(--line)]">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-300">{m.name}</span>
                <span className={`w-2.5 h-2.5 rounded-full ${m.is_trained ? 'bg-emerald-400' : 'bg-rose-400'}`} />
              </div>
              <p className="text-xs text-slate-500 font-mono mb-2">{m.file}</p>
              <span className="text-xs font-semibold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded">
                {m.target}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
