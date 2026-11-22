import React from 'react';

export default function GlassTooltip({ label, children }) {
  return <span className="group relative inline-flex">
    {children}
    <span role="tooltip" className="pointer-events-none absolute left-1/2 top-full z-50 mt-2 -translate-x-1/2 whitespace-nowrap rounded-xl border border-white/10 bg-[#100d22]/95 px-3 py-2 text-[13px] text-slate-100 opacity-0 shadow-xl backdrop-blur-xl transition-opacity duration-200 group-hover:opacity-100 group-focus-within:opacity-100">{label}</span>
  </span>;
}
