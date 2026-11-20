import React from 'react';

export default function Tooltip({ label, children }) {
  return <span className="group relative inline-flex">
    {children}
    <span role="tooltip" className="pointer-events-none absolute left-1/2 top-full z-50 mt-2 -translate-x-1/2 whitespace-nowrap rounded-lg border border-white/10 bg-slate-950 px-2.5 py-1.5 text-[10px] text-slate-200 opacity-0 shadow-xl transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">{label}</span>
  </span>;
}
