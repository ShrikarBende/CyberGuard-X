import React, { useEffect, useState } from 'react';
import { Accessibility, Radio } from 'lucide-react';

export default function Header({ pageTitle, wsConnected, analyst, onLogout }) {
  const [reduceMotion, setReduceMotion] = useState(() => {
    const saved = window.localStorage.getItem('cyberguardx_reduce_motion');
    return saved === null ? window.matchMedia('(prefers-reduced-motion: reduce)').matches : saved === 'true';
  });

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    document.documentElement.classList.toggle('motion-reduced', reduceMotion);
    document.documentElement.classList.toggle('motion-full', window.localStorage.getItem('cyberguardx_reduce_motion') === 'false');
    const onPreferenceChange = () => {
      if (window.localStorage.getItem('cyberguardx_reduce_motion') === null) setReduceMotion(media.matches);
    };
    media.addEventListener?.('change', onPreferenceChange);
    return () => media.removeEventListener?.('change', onPreferenceChange);
  }, [reduceMotion]);

  const toggleMotion = () => {
    const next = !reduceMotion;
    setReduceMotion(next);
    window.localStorage.setItem('cyberguardx_reduce_motion', String(next));
    document.documentElement.classList.toggle('motion-reduced', next);
    document.documentElement.classList.toggle('motion-full', !next);
    window.dispatchEvent(new Event('cyberguardx-motion-change'));
  };

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-white/[0.07] bg-[#0D1527] px-4 md:px-8">
      <div className="pl-12 md:pl-0">
        <h2 className="text-lg font-bold text-slate-100">{pageTitle}</h2>
        <p className="text-xs text-slate-400">Continuous Behavioral Analysis & Multi-Layer Defense</p>
      </div>

      <div className="flex items-center gap-2 sm:gap-4">
        <button type="button" onClick={toggleMotion} aria-pressed={reduceMotion} aria-label={reduceMotion ? 'Enable motion' : 'Reduce motion'} title={reduceMotion ? 'Enable motion' : 'Reduce motion'} className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 px-2 py-1.5 text-[10px] font-medium text-slate-300 hover:bg-white/5">
          <Accessibility className="h-3.5 w-3.5" /><span className="hidden lg:inline">Reduce motion</span>
        </button>
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
            {(analyst?.username || 'A').slice(0, 2).toUpperCase()}
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-semibold text-slate-200">{analyst?.username || 'Analyst'}</p>
            <p className="text-[10px] text-slate-500 font-mono uppercase">{analyst?.role || 'viewer'}</p>
          </div>
        </div>
        <button onClick={onLogout} className="text-[10px] font-semibold text-slate-400 hover:text-white">Log out</button>
      </div>
    </header>
  );
}

