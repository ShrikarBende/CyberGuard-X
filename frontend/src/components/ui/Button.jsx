import React from 'react';
import { cn } from './cn';

const variants = {
  primary: 'bg-gradient-to-r from-[#3050ff] to-[#673be2] text-white shadow-[0_8px_24px_rgba(48,80,255,.2)] hover:brightness-110',
  ghost: 'border border-white/10 bg-white/[0.035] text-slate-200 backdrop-blur-md hover:bg-white/[0.075]',
  danger: 'border border-rose-400/25 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20',
};

export default function Button({ variant = 'ghost', className, children, ...props }) {
  return <button className={cn('inline-flex items-center justify-center gap-2 rounded-full px-4 py-2.5 text-[14px] font-medium transition duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50', variants[variant] || variants.ghost, className)} {...props}>{children}</button>;
}
