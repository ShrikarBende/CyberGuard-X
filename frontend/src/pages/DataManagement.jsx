import React, { useState, useEffect, useCallback } from 'react';
import {
  Upload, Database, CheckCircle2, Activity,
  AlertCircle, Loader2, FlaskConical, BarChart2, ChevronDown, ChevronUp, Play
} from 'lucide-react';
import { api } from '../services/api';

// ─── Helper: format percentage ─────────────────────────────────────────────
const pct = (v) => (v != null ? (v * 100).toFixed(2) + '%' : '—');
const f4  = (v) => (v != null ? v.toFixed(4) : '—');

// ─── Collapsible section ───────────────────────────────────────────────────
function Collapsible({ title, badge, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-[#1E293B] rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between p-4 bg-[#0D1527] hover:bg-[#111b35] transition-colors"
      >
        <span className="text-xs font-bold text-slate-200 flex items-center gap-2">
          {title}
          {badge && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">
              {badge}
            </span>
          )}
        </span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </button>
      {open && <div className="p-4 bg-[#0D1527]/60 border-t border-[#1E293B]">{children}</div>}
    </div>
  );
}

// ─── Known-Classifier results panel ───────────────────────────────────────
function KnownClassifierPanel({ data }) {
  if (!data) return null;
  const { LightGBM, XGBoost, date, data_hash, excluded_labels } = data;

  const ModelTable = ({ model, name }) => (
    <div className="mb-4">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-xs font-bold text-slate-200">{name}</span>
        <span className="font-mono text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
          Macro-F1: {f4(model?.macro_f1)}
        </span>
        <span className="font-mono text-[10px] text-slate-400">Accuracy: {pct(model?.accuracy)}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[11px] text-slate-300">
          <thead>
            <tr className="border-b border-[#1E293B] text-slate-500">
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
                <tr key={cls} className="border-b border-[#1E293B]/50 hover:bg-[#10182E]/50">
                  <td className="py-1 pr-4 font-mono text-blue-300">{cls}</td>
                  <td className="text-right pr-4">{f4(r?.precision)}</td>
                  <td className="text-right pr-4">{f4(r?.recall)}</td>
                  <td className="text-right pr-4 text-emerald-400 font-semibold">{f4(r?.f1)}</td>
                  <td className="text-right text-slate-500">{r?.support?.toLocaleString()}</td>
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
      <div className="flex flex-wrap gap-3 text-[10px] font-mono text-slate-500">
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
      <div className="flex flex-wrap gap-3 text-[10px] font-mono text-slate-500">
        <span>date: {date?.slice(0, 16).replace('T', ' ')} UTC</span>
        <span>data_hash: {data_hash}</span>
        <span className="text-blue-400">threshold: {threshold_percentile}th pct of known-val scores</span>
      </div>

      {/* Macro-average summary */}
      <div>
        <p className="text-xs font-bold text-slate-300 mb-2">Macro-Average Across All Families</p>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] text-slate-300">
            <thead>
              <tr className="border-b border-[#1E293B] text-slate-500">
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
                  <tr key={det} className="border-b border-[#1E293B]/50 hover:bg-[#10182E]/50">
                    <td className="py-1 pr-4 font-mono text-blue-300">{DETECTOR_LABELS[det]}</td>
                    <td className="text-right pr-4 text-emerald-400 font-semibold">{f4(m?.AUROC)}</td>
                    <td className="text-right pr-4">{f4(m?.FPR_at_95pct_TPR)}</td>
                    <td className="text-right pr-4">{pct(m?.unknown_rejection_rate)}</td>
                    <td className="text-right">{pct(m?.known_false_reject_rate)}</td>
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
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] text-slate-300">
                <thead>
                  <tr className="border-b border-[#1E293B] text-slate-500">
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
                      <tr key={det} className={`border-b border-[#1E293B]/50 hover:bg-[#10182E]/50 ${weak ? 'opacity-60' : ''}`}>
                        <td className="py-1 pr-4 font-mono text-blue-300">
                          {DETECTOR_LABELS[det]}
                          {weak && <span className="ml-2 text-[9px] text-amber-400">⚠ weak</span>}
                        </td>
                        <td className={`text-right pr-4 font-semibold ${d.AUROC >= 0.75 ? 'text-emerald-400' : d.AUROC >= 0.60 ? 'text-yellow-400' : 'text-rose-400'}`}>
                          {f4(d.AUROC)}
                        </td>
                        <td className="text-right pr-4">{f4(d.FPR_at_95pct_TPR)}</td>
                        <td className="text-right pr-4">{pct(d.unknown_rejection_rate)}</td>
                        <td className="text-right">{pct(d.known_false_reject_rate)}</td>
                        <td className="text-right pl-4 text-slate-500 font-mono">{f4(d.threshold_value)}</td>
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
        <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30">
          <p className="text-xs font-bold text-amber-400 mb-2">⚠️ Weak / Suspicious Results</p>
          {warnings.map((w, i) => (
            <p key={i} className="text-[11px] text-amber-300 mb-1">{w}</p>
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
      const res = await api.uploadLogs(file);
      setUploadStatus({ success: true, message: res.message });
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
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-blue-400" /> Data Ingestion &amp; Model Governance
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Upload telemetry, run CICIDS2017 evaluation pipeline, inspect rigorous multi-class + open-set metrics
          </p>
        </div>
      </div>

      {/* CICIDS2017 Evaluation Runner */}
      <div className="bg-[#10182E] border border-blue-500/30 rounded-2xl p-6">
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
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  ALL 8 CSVs MOUNTED
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Leave-one-family-out · 4 detectors · 5 attack families · thresholds from known-val only
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={fetchStatus}
              className="px-4 py-2 rounded-xl bg-[#0D1527] hover:bg-[#111b35] border border-[#1E293B] text-white text-xs font-semibold transition-all flex items-center gap-2"
            >
              <Activity className="w-4 h-4" /> Reload Results
            </button>
            {isAdmin && (
              <button
                onClick={handleRunEvaluation}
                disabled={evalRunning}
                className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold transition-all flex items-center gap-2 shadow-lg shadow-emerald-600/20"
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

        {!evalResults?.available ? (
          <div className="p-6 rounded-xl bg-[#0D1527] border border-dashed border-[#1E293B] text-center">
            <BarChart2 className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="text-xs text-slate-400">No evaluation results yet.</p>
              <p className="text-[11px] text-slate-500 mt-1">
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
                <span key={f} className="font-mono text-[10px] px-2 py-1 rounded bg-[#0D1527] border border-[#1E293B] text-slate-400">
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
        <div className="bg-[#10182E] border border-blue-500/30 rounded-2xl p-6">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h4 className="text-sm font-bold text-slate-200">Held-out CICIDS replay</h4>
              <p className="text-xs text-slate-500 mt-1">Streams prepared rows through the live detector and WebSocket.</p>
              <p className="text-xs text-blue-200 mt-2">{replayStatus?.status || 'idle'} · {replayStatus?.processed || 0} / {replayStatus?.total || 0} rows</p>
              {replayError && <p className="text-xs text-rose-300 mt-2">{replayError}</p>}
              {replayStatus?.error && <p className="text-xs text-rose-300 mt-2">{replayStatus.error}</p>}
            </div>
            {isAdmin && <div className="flex flex-wrap items-end gap-2">
              <label className="text-[10px] text-slate-400">Rows<input type="number" min="1" value={replayN} onChange={(e) => setReplayN(e.target.value)} className="mt-1 block w-24 rounded-lg bg-[#0D1527] border border-[#1E293B] px-2 py-2 text-xs text-white" /></label>
              <label className="text-[10px] text-slate-400">Rows / sec<input type="number" min="0" value={replaySpeed} onChange={(e) => setReplaySpeed(e.target.value)} className="mt-1 block w-24 rounded-lg bg-[#0D1527] border border-[#1E293B] px-2 py-2 text-xs text-white" /></label>
              <button onClick={startReplay} disabled={['queued', 'running', 'stopping'].includes(replayStatus?.status)} className="px-4 py-2 rounded-xl bg-blue-600 disabled:opacity-40 text-xs font-semibold text-white">Start replay</button>
              <button onClick={stopReplay} disabled={!['queued', 'running'].includes(replayStatus?.status)} className="px-4 py-2 rounded-xl bg-rose-700 disabled:opacity-40 text-xs font-semibold text-white">Stop replay</button>
            </div>}
          </div>
        </div>
        <div className="bg-[#10182E] border border-amber-500/30 rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-bold text-slate-200">Synthetic correlation scenarios</h4>
              <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[9px] font-bold tracking-wide text-amber-200">DEMO</span>
            </div>
            <p className="text-xs text-slate-500 mt-1">Loads labelled events only. Run correlation separately from Incident Management.</p>
            <div className="mt-2 flex flex-wrap gap-1.5" aria-label="Four built-in demo scenarios">
              {['multi_stage_takeover', 'brute_force_only', 'benign_admin', 'normal_employee_day'].map((scenario) => (
                <span key={scenario} className="rounded-full border border-amber-500/20 bg-[#0D1527] px-2 py-1 text-[9px] text-amber-100">{scenario.replaceAll('_', ' ')}</span>
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
        <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Security Telemetry Upload</h4>
              <p className="text-xs text-slate-500">Supports CSV &amp; JSON (Auth, Sysmon, Network flows)</p>
            </div>
          </div>
          {canAnalyze ? <div className="border-2 border-dashed border-[#1E293B] hover:border-blue-500/50 rounded-2xl p-8 text-center transition-all bg-[#0D1527]/50">
            <input type="file" id="file-upload" accept=".csv,.json" onChange={handleFileUpload} className="hidden" />
            <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center">
              <Upload className="w-8 h-8 text-slate-500 mb-2" />
              <span className="text-xs font-bold text-slate-200">Click to upload security logs</span>
              <span className="text-[11px] text-slate-500 mt-1">.CSV or .JSON format</span>
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
              {uploadStatus.success ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
              <span>{uploadStatus.message}</span>
            </div>
          )}
        </div>

      </div>

      {/* Model Weights Grid */}
      <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
        <h4 className="text-sm font-bold text-slate-200 mb-4">ML Model Weights &amp; Governance</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {Object.entries(modelStatus?.models || {}).map(([key, m]) => (
            <div key={key} className="p-4 rounded-xl bg-[#0D1527] border border-[#1E293B]">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-300">{m.name}</span>
                <span className={`w-2.5 h-2.5 rounded-full ${m.is_trained ? 'bg-emerald-400' : 'bg-rose-400'}`} />
              </div>
              <p className="text-[11px] text-slate-500 font-mono mb-2">{m.file}</p>
              <span className="text-[10px] font-semibold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded">
                {m.target}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
