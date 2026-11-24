import React, { useState, useEffect, useRef } from 'react';
import { Bot, Send, BookOpen, AlertCircle, User, Loader2 } from '../lib/icons';
import { api } from '../services/api';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';

export default function AIAssistant({ initialIncidentId, initialPrompt = '' }) {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(initialIncidentId || '');
  const [messages, setMessages] = useState([]);
  const [inputQuery, setInputQuery] = useState(initialPrompt || '');
  const [loading, setLoading] = useState(false);
  const [retrievalError, setRetrievalError] = useState('');
  const [incidentLoadError, setIncidentLoadError] = useState('');
  const messagesEndRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const chatRef = useRef(null);
  const animatedMessageCount = useRef(0);

  useEffect(() => {
    if (initialPrompt) setInputQuery(initialPrompt);
  }, [initialPrompt]);

  useEffect(() => {
    if (initialIncidentId) setSelectedIncidentId(initialIncidentId);
  }, [initialIncidentId]);

  useGSAP(() => createMotionScope(chatRef.current, (reduced) => {
    if (messages.length <= animatedMessageCount.current) return;
    animatedMessageCount.current = messages.length;
    const newest = chatRef.current?.querySelector(`[data-message-index="${messages.length - 1}"]`);
    if (newest) gsap.fromTo(newest, { autoAlpha: 0, y: reduced ? 0 : 8 }, { autoAlpha: 1, y: 0, duration: reduced ? 0.18 : motion.duration.base, ease: motion.ease });
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
      }
    }
    loadIncidents();
  }, []);

  useEffect(() => {
    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTo({
        top: messagesContainerRef.current.scrollHeight,
        behavior: 'smooth',
      });
    }
  }, [messages]);

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

  return (
    <div ref={chatRef} className="flex flex-col h-[calc(100vh-190px)] min-h-[520px] bg-[#1F1F1F] border border-[#313131] rounded-2xl overflow-hidden">
      {/* Top Incident Context Bar */}
      <div className="p-4 border-b border-[#313131] bg-[#181818] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">Grounded SOC Investigation Assistant</h3>
            <p className="text-xs text-slate-400">FAISS Vector Search & Evidence Citations (Read-Only Guardrail)</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-semibold">Incident Context:</span>
          <select
            value={selectedIncidentId}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="bg-[#1F1F1F] border border-[#313131] text-xs font-semibold text-slate-200 rounded-xl px-3 py-1.5 focus:outline-none focus:border-purple-500"
          >
            <option value="">General Threat Intelligence</option>
            {incidents.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.title} (#{inc.incident_id.slice(-6)})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Messages Scroll Area */}
      {!incidents.length ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-400">
          <AlertCircle className="w-8 h-8 text-slate-600 mb-3" />
          <p className="text-sm font-semibold">No incident selected.</p>
          <p className="text-xs mt-2">Load or select an incident to ask evidence-grounded investigation questions.</p>
          {incidentLoadError && <p role="alert" className="text-xs text-rose-300 mt-3">{incidentLoadError}</p>}
        </div>
      ) : !selectedIncidentId ? (
        <div className="flex-1 flex items-center justify-center text-slate-400 text-xs">Select an incident to begin.</div>
      ) : (
      <div ref={messagesContainerRef} className="flex-1 overflow-y-auto overscroll-contain p-6 space-y-4">
        {retrievalError && (
          <div role="alert" className="p-3 rounded-xl border border-rose-500/30 bg-rose-500/10 text-xs text-rose-200 flex items-center gap-2">
            <AlertCircle className="w-4 h-4" /> Retrieval error: {retrievalError}
          </div>
        )}
        {messages.map((msg, idx) => {
          const isUser = msg.sender === 'user';
          return (
            <div
              key={idx}
              data-message-index={idx}
              className={`flex gap-3 max-w-3xl ${isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'}`}
            >
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 text-xs font-bold ${
                  isUser ? 'bg-blue-600 text-white' : 'bg-purple-600 text-white'
                }`}
              >
                {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              <div
                className={`p-4 rounded-2xl text-xs space-y-3 leading-relaxed ${
                  isUser
                    ? 'bg-blue-600 text-white rounded-tr-none'
                    : 'bg-[#181818] border border-[#313131] text-slate-200 rounded-tl-none shadow-md'
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.text}</div>

                {!isUser && msg.mode && (
                  <span className="inline-flex rounded-full border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-[10px] uppercase tracking-wide text-purple-300">
                    {msg.mode}
                  </span>
                )}

                {/* Retrieved sources */}
                {!isUser && msg.sources && msg.sources.length > 0 && (
                  <div className="pt-2 border-t border-[#313131] flex flex-wrap gap-2">
                    <span className="text-[10px] font-bold text-slate-400 flex items-center gap-1 uppercase">
                      <BookOpen className="w-3 h-3 text-purple-400" /> Retrieved Sources:
                    </span>
                    {msg.sources.map((source, cIdx) => (
                      <span
                        key={cIdx}
                        className="rounded-lg border border-purple-400/20 bg-purple-400/[0.06] px-2.5 py-1 text-[10px] font-mono text-purple-200"
                      >
                        {source.chunk_id}: {source.title} · {Number(source.score).toFixed(3)}
                      </span>
                    ))}
                  </div>
                )}

                {!isUser && msg.evidenceUsed?.length > 0 && (
                  <details className="pt-2 border-t border-[#313131]">
                    <summary className="cursor-pointer text-[10px] font-bold uppercase text-slate-400">Stored evidence used</summary>
                    <pre className="mt-2 whitespace-pre-wrap break-all text-[10px] text-slate-400">{JSON.stringify(msg.evidenceUsed, null, 2)}</pre>
                  </details>
                )}
              </div>
            </div>
          );
        })}
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 text-xs italic">
            <Loader2 className="w-4 h-4 animate-spin text-purple-400" />
            Analyzing incident evidence and retrieving ATT&CK techniques...
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>
      )}

      {/* Quick Prompts Bar */}
      <div className="px-6 py-2 bg-[#181818] border-t border-[#313131] flex items-center gap-2 overflow-x-auto no-scrollbar">
        <span className="text-[10px] text-slate-500 font-bold uppercase shrink-0">Prompts:</span>
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(p)}
            disabled={!selectedIncidentId || loading}
            className="px-2.5 py-1 rounded-lg bg-[#1F1F1F] hover:bg-[#313131] border border-[#313131] text-[11px] text-slate-300 whitespace-nowrap transition-colors"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <form onSubmit={(e) => { e.preventDefault(); handleSend(); }} className="p-4 bg-[#181818] border-t border-[#313131] flex gap-3">
        <input
          type="text"
          aria-label="Ask about detected anomalies, attack classification, or containment"
          placeholder="Ask about detected anomalies, attack classification, or containment..."
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          className="flex-1 bg-[#1F1F1F] border border-[#313131] text-slate-200 text-xs rounded-xl px-4 py-3 focus:outline-none focus:border-purple-500"
        />
        <button
          type="submit"
          disabled={loading || !inputQuery.trim() || !selectedIncidentId}
          className="px-5 py-3 rounded-xl bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-xs font-semibold transition-all flex items-center gap-2 shadow-lg shadow-purple-600/20"
        >
          <Send className="w-4 h-4" /> Send
        </button>
      </form>
    </div>
  );
}

