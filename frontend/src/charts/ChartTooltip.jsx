import React from 'react';

export default function ChartTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return <div className="min-w-32 rounded-xl border border-white/10 bg-slate-950/95 p-3 shadow-2xl backdrop-blur-xl">
    {label != null && <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">{label}</p>}
    <div className="space-y-1.5">{payload.map((item, index) => {
      const formatted = formatter ? formatter(item.value, item.name, item) : [item.value, item.name];
      return <div key={`${item.dataKey || item.name}-${index}`} className="flex items-center justify-between gap-5 text-xs">
        <span className="flex items-center gap-2 text-slate-300"><i className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color || item.fill }} />{formatted[1] || item.name}</span>
        <span className="soc-mono font-medium text-slate-100">{formatted[0]}</span>
      </div>;
    })}</div>
  </div>;
}
