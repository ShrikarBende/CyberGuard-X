import React from 'react';
import { cn } from './cn';

export default function EmptyState({ icon: Icon, title, description, className, children }) {
  return <div className={cn('flex min-h-36 flex-col items-center justify-center rounded-[var(--r-inner)] border border-transparent bg-transparent px-6 py-8 text-center', className)}>
    {Icon && <Icon aria-hidden="true" className="mb-3 h-6 w-6 text-[var(--muted)]" />}
    {title && <p className="text-sm font-semibold text-[var(--ink)]">{title}</p>}
    {description && <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-[var(--muted)]">{description}</p>}
    {children}
  </div>;
}
