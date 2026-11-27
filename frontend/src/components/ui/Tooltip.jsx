import React from 'react';

export default function Tooltip({ label, children }) {
  return <span className="group relative inline-flex">
    {children}
    <span role="tooltip" className="glass pointer-events-none absolute left-1/2 top-full z-50 mt-2 -translate-x-1/2 whitespace-nowrap rounded-lg px-3 py-2 text-xs text-[var(--ink)] opacity-0 transition-opacity duration-200 group-hover:opacity-100 group-focus-within:opacity-100">{label}</span>
  </span>;
}
