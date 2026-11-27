import React from 'react';
import { cn } from './cn';

export default function Toggle({ checked = false, onChange, label, disabled = false, className }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange?.(!checked)} className={cn('inline-flex items-center gap-3 text-left text-sm text-slate-200 disabled:cursor-not-allowed disabled:opacity-50', className)}>
    <span aria-hidden="true" className={`relative h-[26px] w-11 rounded-full border border-transparent transition-colors duration-200 ${checked ? 'bg-[var(--cobalt)]' : 'bg-[var(--line)]'}`}>
      <span className={`absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white shadow-[0_1px_3px_rgba(18,20,28,.18)] transition-transform duration-200 ${checked ? 'translate-x-[18px]' : ''}`} />
    </span>
    {label && <span>{label}</span>}
  </button>;
}
