import React from 'react';
import { cn } from './cn';

export default function ErrorState({ title = 'Something went wrong', description, onRetry, className }) {
  return <section role="alert" className={cn('rounded-[var(--r-card)] border border-transparent bg-[var(--critical-tint)] p-5 text-[var(--critical)]', className)}>
    <h3 className="text-sm font-semibold">{title}</h3>
    {description && <p className="mt-1 text-sm text-[var(--muted)]">{description}</p>}
    {onRetry && <button type="button" onClick={onRetry} className="mt-4 rounded-full border border-transparent bg-white px-4 py-2 text-sm font-semibold text-[var(--ink)] hover:bg-[var(--chip)]">Try again</button>}
  </section>;
}
