import React from 'react';
import { cn } from './cn';

export default function Toggle({ checked = false, onChange, label, disabled = false, className }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange?.(!checked)} className={cn('inline-flex items-center gap-3 text-left text-[14px] text-slate-200 disabled:cursor-not-allowed disabled:opacity-50', className)}>
    <span aria-hidden="true" className={`relative h-6 w-11 rounded-full border transition-colors duration-200 ${checked ? 'border-blue-300/40 bg-blue-500' : 'border-white/15 bg-white/10'}`}>
      <span className={`absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform duration-200 ${checked ? 'translate-x-[22px]' : ''}`} />
    </span>
    {label && <span>{label}</span>}
  </button>;
}
