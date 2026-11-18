import React from 'react';
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
} from 'lucide-react';

export default function Sidebar({ activePage, setActivePage, role }) {
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
    <aside className="w-64 bg-[#0D1527] border-r border-[#1E293B] flex flex-col justify-between shrink-0">
      <div>
        {/* Brand Logo */}
        <div className="h-16 flex items-center gap-3 px-6 border-b border-[#1E293B]">
          <div className="w-9 h-9 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-slate-100 text-sm tracking-wide">CyberGuard X</h1>
            <p className="text-[10px] text-blue-400 font-mono uppercase tracking-wider">Enterprise SOC</p>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1">
          {visibleItems.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#131D38]'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-[#1E293B] m-2 rounded-xl bg-[#10182E]">
        <div className="flex items-center gap-2 mb-1.5">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
          <span className="text-xs font-semibold text-slate-300">Open-Set Engine Online</span>
        </div>
        <p className="text-[11px] text-slate-500">
          3-Layer Correlation active (User, Endpoint, Network).
        </p>
      </div>
    </aside>
  );
}

