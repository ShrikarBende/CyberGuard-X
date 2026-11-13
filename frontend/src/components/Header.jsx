import React from 'react';
import { Shield, Bell, Cpu, Radio } from 'lucide-react';

export default function Header({ pageTitle, wsConnected }) {
  return (
    <header className="h-16 bg-[#0D1527] border-b border-[#1E293B] px-8 flex items-center justify-between shrink-0">
      <div>
        <h2 className="text-lg font-bold text-slate-100">{pageTitle}</h2>
        <p className="text-xs text-slate-400">Continuous Behavioral Analysis & Multi-Layer Defense</p>
      </div>

      <div className="flex items-center gap-4">
        {/* WebSocket Live Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#10182E] border border-[#1E293B] text-xs">
          <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
          <span className="font-mono text-[11px] text-slate-300">
            {wsConnected ? 'WS STREAM: CONNECTED' : 'WS STREAM: POLLING'}
          </span>
        </div>

        {/* Analyst Profile */}
        <div className="flex items-center gap-2.5 pl-4 border-l border-[#1E293B]">
          <div className="w-8 h-8 rounded-full bg-blue-500/20 border border-blue-500/40 flex items-center justify-center text-blue-400 font-bold text-xs">
            SA
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-semibold text-slate-200">Security Analyst</p>
            <p className="text-[10px] text-slate-500 font-mono">SOC Tier-2</p>
          </div>
        </div>
      </div>
    </header>
  );
}

