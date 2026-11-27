import React from 'react';

export default function GlassTooltip({ label, children }) {
  return <span className="group relative inline-flex">
    {children}
    <span role="tooltip" className="glass pointer-events-none !absolute left-1/2 top-full z-50 mt-2 w-max max-w-[min(22rem,calc(100vw_-_2rem))] -translate-x-1/2 whitespace-normal rounded-lg px-3 py-2 text-xs text-[var(--ink)] opacity-0 transition-opacity duration-200 group-hover:opacity-100 group-focus-within:opacity-100 md:left-full md:top-1/2 md:ml-4 md:mt-0 md:translate-x-0 md:-translate-y-1/2">{label}</span>
  </span>;
}
