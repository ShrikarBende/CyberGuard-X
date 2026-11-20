import React from 'react';
import { cn } from './cn';

const variants = {
  primary: 'bg-gradient-to-r from-blue-500 to-violet-500 text-white shadow-lg shadow-blue-950/40 hover:brightness-110',
  ghost: 'border border-white/10 bg-white/[0.035] text-slate-200 hover:bg-white/[0.075]',
  danger: 'border border-rose-400/25 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20',
};

export default function Button({ variant = 'ghost', className, children, ...props }) {
  return <button className={cn('inline-flex items-center justify-center gap-2 rounded-xl px-3.5 py-2.5 text-xs font-semibold transition duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50', variants[variant] || variants.ghost, className)} {...props}>{children}</button>;
}
