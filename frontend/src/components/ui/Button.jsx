import React from 'react';
import { cn } from './cn';

const variants = {
  primary: 'border border-transparent bg-[var(--cobalt)] text-white hover:bg-[var(--cobalt-hover)]',
  ghost: 'border border-transparent bg-[var(--chip)] text-[var(--ink)] hover:bg-[var(--line)]',
  danger: 'border border-transparent bg-[var(--critical-tint)] text-[var(--critical)] hover:bg-[#f9d8d1]',
};

export default function Button({ variant = 'ghost', className, children, ...props }) {
  return <button className={cn('inline-flex items-center justify-center gap-2 rounded-full px-4 py-2.5 text-sm font-semibold transition duration-150 disabled:cursor-not-allowed disabled:opacity-50', variant === 'primary' && 'soc-primary-button', variants[variant] || variants.ghost, className)} {...props}>{children}</button>;
}
