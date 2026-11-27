import React from 'react';

export default function ChartTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return <div className="glass min-w-32 rounded-xl p-3 text-[var(--ink)]">
    {label != null && <p className="mb-2 text-xs font-semibold text-[var(--muted)]">{label}</p>}
    <div className="space-y-1.5">{payload.map((item, index) => {
      const formatted = formatter ? formatter(item.value, item.name, item) : [item.value, item.name];
      return <div key={`${item.dataKey || item.name}-${index}`} className="flex items-center justify-between gap-5 text-xs">
        <span className="flex items-center gap-2 text-[var(--muted)]"><i className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color || item.fill }} />{formatted[1] || item.name}</span>
        <span className="soc-mono font-medium text-[var(--ink)]">{formatted[0]}</span>
      </div>;
    })}</div>
  </div>;
}
