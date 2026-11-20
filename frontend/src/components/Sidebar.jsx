import React, { useState } from 'react';
import {
  ShieldAlert,
  Activity,
  Radar,
  FileWarning,
  Sparkles,
  Bot,
  Database,
  Layers,
  BarChart3,
  Menu,
  X,
} from 'lucide-react';

export default function Sidebar({ activePage, setActivePage, role }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const navItems = [
    { id: 'overview', label: 'Overview Dashboard', icon: Activity },
    { id: 'live', label: 'Live Monitoring', icon: Radar },
    { id: 'threats', label: 'Threat Intelligence', icon: ShieldAlert },
    { id: 'incidents', label: 'Incident Management', icon: FileWarning },
    { id: 'explain', label: 'SHAP Explainability', icon: Sparkles },
    { id: 'assistant', label: 'AI Security Assistant', icon: Bot },
    { id: 'data', label: 'Data & Model Training', icon: Database },
    { id: 'evaluation', label: 'Evaluation Summary', icon: BarChart3 },
  ];

  const visibleItems = navItems.filter((item) => (
    role !== 'viewer' || item.id !== 'assistant'
  ));

  return (
    <>
    {!mobileOpen && <button type="button" onClick={() => setMobileOpen(true)} aria-label="Open navigation" className="fixed left-3 top-3 z-50 flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-slate-900 text-slate-200 shadow-xl md:hidden"><Menu className="h-5 w-5" /></button>}
    {mobileOpen && <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation" className="fixed inset-0 z-40 bg-black/60 md:hidden" />}
    <aside className={`z-50 flex shrink-0 flex-col justify-between border-r border-white/[0.07] bg-[#0d1527] transition-transform duration-200 max-md:fixed max-md:inset-y-0 max-md:left-0 max-md:w-64 ${mobileOpen ? 'max-md:translate-x-0' : 'max-md:-translate-x-full'} w-16 xl:w-64`}>
      <div>
        {/* Brand Logo */}
        <div className="flex h-16 items-center justify-center gap-3 border-b border-white/[0.07] px-2 xl:justify-start xl:px-6 max-md:justify-start max-md:px-4">
          <div className="w-9 h-9 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <Layers className="w-5 h-5" />
          </div>
          <div className="hidden xl:block max-md:block">
            <h1 className="font-display text-sm font-bold tracking-wide text-slate-100">CyberGuard X</h1>
            <p className="text-[10px] text-blue-400 font-mono uppercase tracking-wider">Enterprise SOC</p>
          </div>
          <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation" className="ml-auto rounded-lg p-2 text-slate-400 hover:bg-white/5 hover:text-white md:hidden"><X className="h-4 w-4" /></button>
        </div>

        {/* Navigation Items */}
        <nav className="space-y-1 p-2 xl:p-3">
          {visibleItems.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => { setActivePage(item.id); setMobileOpen(false); }}
                aria-current={isActive ? 'page' : undefined}
                title={item.label}
                className={`flex w-full items-center justify-center gap-3 rounded-xl px-2 py-3 text-xs font-medium transition-all xl:justify-start xl:px-3.5 xl:py-2.5 max-md:justify-start max-md:px-3.5 ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#131D38]'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                <span className="hidden xl:inline max-md:inline">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="m-2 hidden rounded-xl border-t border-white/[0.07] bg-[#10182E] p-4 xl:block max-md:block">
        <div className="flex items-center gap-2 mb-1.5">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
          <span className="text-xs font-semibold text-slate-300">Open-Set Engine Online</span>
        </div>
        <p className="text-[11px] text-slate-500">
          3-Layer Correlation active (User, Endpoint, Network).
        </p>
      </div>
    </aside>
    </>
  );
}

