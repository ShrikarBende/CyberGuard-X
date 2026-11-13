import React, { useState, useEffect, useRef } from 'react';
import { Bot, Send, Sparkles, BookOpen, ShieldCheck, AlertCircle, User, Loader2 } from 'lucide-react';
import { api } from '../services/api';

export default function AIAssistant({ initialIncidentId }) {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(initialIncidentId || '');
  const [messages, setMessages] = useState([
    {
      sender: 'assistant',
      text: 'Hello, I am CyberGuard X Assistant. I am grounded in your enterprise incident evidence and the MITRE ATT&CK framework. Select an incident or ask an investigative query below.',
      citations: [],
      containment: [],
    },
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

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
      }
    }
    loadIncidents();
  }, [selectedIncidentId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async (queryToSend = null) => {
    const q = queryToSend || inputQuery;
    if (!q.trim() || loading) return;

    const userMsg = { sender: 'user', text: q };
    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const response = await api.ragChat(q, selectedIncidentId || null);
      const assistantMsg = {
        sender: 'assistant',
        text: response.answer,
        citations: response.citations || [],
        containment: response.recommended_containment || [],
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: 'Encountered an error while querying knowledge base. Please ensure backend is running.',
          citations: [],
          containment: [],
        },
      ]);
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
    <div className="flex flex-col h-[calc(100vh-140px)] bg-[#10182E] border border-[#1E293B] rounded-2xl overflow-hidden">
      {/* Top Incident Context Bar */}
      <div className="p-4 border-b border-[#1E293B] bg-[#0D1527] flex flex-wrap items-center justify-between gap-4">
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
            className="bg-[#10182E] border border-[#1E293B] text-xs font-semibold text-slate-200 rounded-xl px-3 py-1.5 focus:outline-none focus:border-purple-500"
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
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.map((msg, idx) => {
          const isUser = msg.sender === 'user';
          return (
            <div
              key={idx}
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
                    : 'bg-[#0D1527] border border-[#1E293B] text-slate-200 rounded-tl-none shadow-md'
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.text}</div>

                {/* Citations */}
                {!isUser && msg.citations && msg.citations.length > 0 && (
                  <div className="pt-2 border-t border-[#1E293B] flex flex-wrap gap-2">
                    <span className="text-[10px] font-bold text-slate-400 flex items-center gap-1 uppercase">
                      <BookOpen className="w-3 h-3 text-purple-400" /> Grounded Citations:
                    </span>
                    {msg.citations.map((c, cIdx) => (
                      <span
                        key={cIdx}
                        className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-[10px] font-mono text-purple-300"
                      >
                        {c.doc_id}: {c.title}
                      </span>
                    ))}
                  </div>
                )}

                {/* Containment Steps */}
                {!isUser && msg.containment && msg.containment.length > 0 && (
                  <div className="p-3 rounded-xl bg-[#10182E] border border-emerald-500/20">
                    <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1 uppercase mb-1">
                      <ShieldCheck className="w-3.5 h-3.5" /> Recommended Remediation (Analyst Action Required):
                    </span>
                    <ul className="list-disc list-inside space-y-1 text-slate-300 text-[11px]">
                      {msg.containment.map((step, sIdx) => (
                        <li key={sIdx}>{step}</li>
                      ))}
                    </ul>
                  </div>
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

      {/* Quick Prompts Bar */}
      <div className="px-6 py-2 bg-[#0D1527] border-t border-[#1E293B] flex items-center gap-2 overflow-x-auto no-scrollbar">
        <span className="text-[10px] text-slate-500 font-bold uppercase shrink-0">Prompts:</span>
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(p)}
            className="px-2.5 py-1 rounded-lg bg-[#10182E] hover:bg-[#1E293B] border border-[#1E293B] text-[11px] text-slate-300 whitespace-nowrap transition-colors"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <form onSubmit={(e) => { e.preventDefault(); handleSend(); }} className="p-4 bg-[#0D1527] border-t border-[#1E293B] flex gap-3">
        <input
          type="text"
          placeholder="Ask about detected anomalies, attack classification, or containment..."
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          className="flex-1 bg-[#10182E] border border-[#1E293B] text-slate-200 text-xs rounded-xl px-4 py-3 focus:outline-none focus:border-purple-500"
        />
        <button
          type="submit"
          disabled={loading || !inputQuery.trim()}
          className="px-5 py-3 rounded-xl bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-xs font-semibold transition-all flex items-center gap-2 shadow-lg shadow-purple-600/20"
        >
          <Send className="w-4 h-4" /> Send
        </button>
      </form>
    </div>
  );
}

