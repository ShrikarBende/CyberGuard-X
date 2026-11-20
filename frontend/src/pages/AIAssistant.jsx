import React, { useState, useEffect, useRef } from 'react';
import { Bot, Send, BookOpen, AlertCircle, User, Loader2, Copy, Check, ShieldCheck } from 'lucide-react';
import { api } from '../services/api';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import EmptyState from '../components/ui/EmptyState';
import Skeleton from '../components/ui/Skeleton';

export default function AIAssistant({ initialIncidentId }) {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(initialIncidentId || '');
  const [messages, setMessages] = useState([]);
  const [inputQuery, setInputQuery] = useState('');
  const [incidentLoading, setIncidentLoading] = useState(true);
  const [loading, setLoading] = useState(false);
  const [retrievalError, setRetrievalError] = useState('');
  const [incidentLoadError, setIncidentLoadError] = useState('');
  const [copiedMessage, setCopiedMessage] = useState(-1);
  const messagesEndRef = useRef(null);
  const chatRef = useRef(null);
  const scrollAreaRef = useRef(null);
  const autoScroll = useRef(true);
  const animatedMessageCount = useRef(0);

  useGSAP(() => createMotionScope(chatRef.current, (reduced) => {
    if (messages.length <= animatedMessageCount.current) return;
    animatedMessageCount.current = messages.length;
    const newest = chatRef.current?.querySelector(`[data-message-index="${messages.length - 1}"]`);
    if (newest) gsap.fromTo(newest, { opacity: 0, y: reduced ? 0 : 8 }, { opacity: 1, y: 0, duration: reduced ? 0.18 : motion.duration.base, ease: motion.ease });
  }), { scope: chatRef, dependencies: [messages], revertOnUpdate: true });

  useEffect(() => {
    async function loadIncidents() {
      try {
        const data = await api.getIncidents();
        setIncidents(data);
        if (data.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data[0].incident_id);
        }
      } catch (err) {
        console.error(err);
        setIncidentLoadError(err.message || 'Could not load incidents.');
      } finally { setIncidentLoading(false); }
    }
    loadIncidents();
  }, []);

  useEffect(() => {
    if (!autoScroll.current) return;
    scrollAreaRef.current?.scrollTo({ top: scrollAreaRef.current.scrollHeight, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  }, [messages]);

  const trackScroll = () => {
    const area = scrollAreaRef.current;
    if (!area) return;
    autoScroll.current = area.scrollHeight - area.scrollTop - area.clientHeight < 96;
  };

  const copyMessage = async (text, index) => {
    if (!navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedMessage(index);
      window.setTimeout(() => setCopiedMessage(-1), 1400);
    } catch { /* Clipboard access may be unavailable outside a secure context. */ }
  };

  const handleSend = async (queryToSend = null) => {
    const q = queryToSend || inputQuery;
    if (!q.trim() || loading) return;

    const userMsg = { sender: 'user', text: q };
    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);
    setRetrievalError('');

    try {
      const response = await api.ragChat(q, selectedIncidentId || null);
      const assistantMsg = {
        sender: 'assistant',
        text: response.answer,
        mode: response.mode,
        sources: response.sources || [],
        evidenceUsed: response.evidence_used || [],
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setRetrievalError(err.message || 'Retrieval failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const quickPrompts = [
    'Why was this threat classified as unknown / novel?',
    'What evidence supports this detection?',
    'What attack technique might be involved?',
    'What are the recommended containment steps?',
  ];
  const selectedIncident = incidents.find((incident) => incident.incident_id === selectedIncidentId);
  const severityTone = (severity) => ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', BENIGN: 'normal', NORMAL: 'normal', UNKNOWN_NOVEL: 'novel' }[String(severity || '').toUpperCase()] || 'neutral');

  return (
    <div ref={chatRef} className="mx-auto flex h-[calc(100dvh-140px)] min-h-[420px] w-full max-w-[1600px] flex-col overflow-hidden rounded-2xl border border-white/[0.08] bg-[var(--soc-panel)] shadow-[inset_0_1px_0_rgba(255,255,255,0.035)]">
      <header className="shrink-0 border-b border-white/[0.08] bg-[var(--soc-raised)]/90 p-4 sm:px-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl border border-purple-400/20 bg-purple-400/10 text-purple-200"><Bot className="h-5 w-5" /></div>
            <div><h3 className="text-sm font-bold text-slate-100">Grounded SOC Investigation Assistant</h3><p className="mt-0.5 text-xs text-slate-400">FAISS Vector Search &amp; Evidence Citations (Read-Only Guardrail)</p></div>
          </div>
          <Badge tone="normal" className="gap-1.5 px-3 py-1.5 text-[11px]"><ShieldCheck className="h-3.5 w-3.5" />Read-only guardrail</Badge>
        </div>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-black/15 px-3 py-2.5 sm:px-4">
          <div className="min-w-0"><p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Incident Context</p>{selectedIncident ? <div className="mt-1 flex flex-wrap items-center gap-2"><Badge tone={severityTone(selectedIncident.severity)}>{selectedIncident.severity}</Badge><span className="truncate text-xs font-semibold text-slate-100">{selectedIncident.title}</span><span className="font-mono text-[11px] tabular-nums text-slate-400">#{selectedIncident.incident_id.slice(-6)}</span></div> : <p className="mt-1 text-xs font-medium text-slate-300">General Threat Intelligence</p>}</div>
          <label className="flex items-center gap-2 text-[11px] font-medium text-slate-400"><span className="sr-only">Incident Context:</span><select value={selectedIncidentId} onChange={(e) => setSelectedIncidentId(e.target.value)} className="max-w-[min(72vw,26rem)] rounded-lg border border-white/[0.1] bg-[var(--soc-panel)] px-3 py-2 text-xs font-semibold text-slate-200 outline-none transition focus-visible:ring-2 focus-visible:ring-purple-400">
            <option value="">General Threat Intelligence</option>
            {incidents.map((inc) => <option key={inc.incident_id} value={inc.incident_id}>{inc.title} (#{inc.incident_id.slice(-6)})</option>)}
          </select></label>
        </div>
      </header>

      <div ref={scrollAreaRef} onScroll={trackScroll} className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-5 sm:px-6" aria-live="polite" aria-busy={incidentLoading || loading}>
        {incidentLoading ? <div className="mx-auto w-full max-w-[820px] space-y-4 py-8"><Skeleton className="mx-auto h-12 w-12 rounded-2xl" /><Skeleton className="mx-auto h-5 w-64 max-w-full" /><Skeleton className="h-24 rounded-2xl" /><Skeleton className="h-24 rounded-2xl" /></div>
          : !incidents.length ? <div className="mx-auto flex min-h-full max-w-[820px] flex-col items-center justify-center text-center"><EmptyState icon={AlertCircle} title="No incident selected." description="Load or select an incident to ask evidence-grounded investigation questions." className="w-full border-transparent bg-transparent" />{incidentLoadError && <p role="alert" className="mt-3 text-xs text-rose-300">{incidentLoadError}</p>}</div>
            : !selectedIncidentId ? <div className="mx-auto flex min-h-full max-w-[820px] items-center justify-center text-center"><EmptyState icon={AlertCircle} title="Select an incident to begin." className="w-full border-transparent bg-transparent" /></div>
              : messages.length === 0 ? <section className="mx-auto flex min-h-full w-full max-w-[820px] flex-col items-center justify-center py-6 text-center">
                <div className="mb-4 grid h-14 w-14 place-items-center rounded-2xl border border-purple-300/20 bg-gradient-to-br from-purple-400/15 to-blue-400/10 text-purple-200 shadow-[0_0_32px_rgba(168,85,247,0.12)]"><Bot className="h-7 w-7" /></div>
                <h2 className="text-xl font-bold tracking-tight text-slate-100">Start with a question</h2>
                <p className="mt-2 max-w-lg text-xs leading-relaxed text-slate-400">FAISS Vector Search &amp; Evidence Citations (Read-Only Guardrail)</p>
                <div className="mt-7 grid w-full gap-3 text-left sm:grid-cols-2">{quickPrompts.map((prompt) => <button key={prompt} type="button" onClick={() => handleSend(prompt)} disabled={!selectedIncidentId || loading} className="group min-h-20 rounded-xl border border-white/[0.08] bg-white/[0.025] p-4 text-left text-xs font-medium leading-relaxed text-slate-300 transition duration-150 hover:-translate-y-0.5 hover:border-purple-300/20 hover:bg-purple-400/[0.045] hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple-300 disabled:cursor-not-allowed disabled:opacity-50"><span className="mb-2 block text-purple-300"><Sparkles className="h-4 w-4" /></span>{prompt}</button>)}</div>
              </section>
              : <div className="mx-auto w-full max-w-[820px] space-y-5">
                {retrievalError && <div role="alert" className="flex items-center gap-2 rounded-xl border border-rose-500/25 bg-rose-500/[0.08] p-3 text-xs text-rose-200"><AlertCircle className="h-4 w-4 shrink-0" /> Retrieval error: {retrievalError}</div>}
                {messages.map((msg, idx) => {
                  const isUser = msg.sender === 'user';
                  return <div key={idx} data-message-index={idx} className={`flex max-w-full gap-3 ${isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'}`}>
                    <div aria-hidden="true" className={`grid h-8 w-8 shrink-0 place-items-center rounded-xl border ${isUser ? 'border-blue-300/20 bg-blue-400/10 text-blue-200' : 'border-purple-300/20 bg-purple-400/10 text-purple-200'}`}>{isUser ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}</div>
                    <div className={`min-w-0 max-w-[min(100%,680px)] rounded-2xl p-4 text-xs leading-relaxed ${isUser ? 'rounded-tr-sm border border-blue-300/15 bg-blue-500/10 text-blue-50' : 'rounded-tl-sm border border-white/[0.08] bg-[var(--soc-raised)] text-slate-200 shadow-[inset_0_1px_0_rgba(255,255,255,0.035)]'}`}>
                      <div className="whitespace-pre-wrap break-words">{msg.text}</div>
                      {!isUser && <div className="mt-3 flex flex-wrap items-center gap-2">{msg.mode && <Badge tone="novel" className="uppercase">{msg.mode}</Badge>}<button type="button" aria-label="Copy assistant response" onClick={() => copyMessage(msg.text, idx)} className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-2 py-1 text-[11px] text-slate-400 transition hover:bg-white/[0.05] hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">{copiedMessage === idx ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Copy className="h-3.5 w-3.5" />}{copiedMessage === idx ? 'Copied' : 'Copy'}</button></div>}
                      {!isUser && msg.sources?.length > 0 && <div className="mt-3 border-t border-white/[0.08] pt-3"><span className="mb-2 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wide text-slate-400"><BookOpen className="h-3.5 w-3.5 text-purple-300" /> Retrieved Sources:</span><div className="flex flex-wrap gap-2">{msg.sources.map((source, cIdx) => <span key={cIdx} className="rounded-lg border border-purple-300/15 bg-purple-400/[0.05] px-2.5 py-1.5 text-[11px] text-purple-100"><span className="font-mono tabular-nums text-purple-200">{source.chunk_id}</span><span className="text-slate-400"> · </span>{source.title}<span className="ml-2 font-mono tabular-nums text-slate-400">{Number(source.score).toFixed(3)}</span></span>)}</div></div>}
                      {!isUser && msg.evidenceUsed?.length > 0 && <details className="mt-3 border-t border-white/[0.08] pt-3"><summary className="cursor-pointer text-[11px] font-bold uppercase text-slate-400">Stored evidence used</summary><pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-slate-400">{JSON.stringify(msg.evidenceUsed, null, 2)}</pre></details>}
                    </div>
                  </div>;
                })}
                {loading && <div className="flex items-center gap-2 rounded-xl border border-purple-300/10 bg-purple-400/[0.04] px-3 py-2.5 text-xs text-slate-300" role="status"><Loader2 className="h-4 w-4 animate-spin text-purple-300" /> Analyzing incident evidence and retrieving ATT&amp;CK techniques...</div>}
                <div />
              </div>}
      </div>

      {messages.length > 0 && <div className="shrink-0 border-t border-white/[0.07] bg-[var(--soc-raised)] px-4 py-2 sm:px-6"><div className="mx-auto flex max-w-[820px] items-center gap-2 overflow-x-auto no-scrollbar"><span className="shrink-0 text-[11px] font-bold uppercase text-slate-400">Prompts:</span>{quickPrompts.map((prompt) => <button key={prompt} type="button" onClick={() => handleSend(prompt)} disabled={!selectedIncidentId || loading} className="shrink-0 rounded-lg border border-white/[0.08] bg-white/[0.025] px-2.5 py-1.5 text-[11px] text-slate-300 transition-colors hover:bg-white/[0.07] disabled:opacity-50">{prompt}</button>)}</div></div>}

      <form onSubmit={(e) => { e.preventDefault(); handleSend(); }} className="sticky bottom-0 z-10 shrink-0 border-t border-white/[0.08] bg-[var(--soc-raised)]/95 p-3 backdrop-blur-xl sm:px-6 sm:py-4">
        <div className="mx-auto flex max-w-[820px] gap-2 rounded-2xl border border-white/[0.1] bg-[var(--soc-panel)] p-1.5 shadow-[0_0_0_0_rgba(139,92,246,0)] transition-shadow focus-within:border-purple-300/30 focus-within:shadow-[0_0_24px_rgba(139,92,246,0.1)] sm:gap-3 sm:p-2">
          <input type="text" aria-label="Ask about detected anomalies, attack classification, or containment" placeholder="Ask about detected anomalies, attack classification, or containment..." value={inputQuery} onChange={(e) => setInputQuery(e.target.value)} className="min-w-0 flex-1 bg-transparent px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500" />
          <Button type="submit" variant="primary" disabled={loading || !inputQuery.trim() || !selectedIncidentId} className="min-w-24 px-4"><Send className="h-4 w-4" />{loading ? 'Sending…' : 'Send'}</Button>
        </div>
      </form>
    </div>
  );
}

