import React from 'react';
import { cn } from './cn';

export default function EmptyState({ icon: Icon, title, description, className, children }) {
  return <div className={cn('flex min-h-36 flex-col items-center justify-center rounded-[22px] border border-white/[0.08] bg-gradient-to-b from-white/[0.025] to-transparent px-6 py-8 text-center', className)}>
    {Icon && <Icon aria-hidden="true" className="mb-3 h-6 w-6 text-slate-500" />}
    {title && <p className="text-[15px] font-medium text-slate-200">{title}</p>}
    {description && <p className="mt-1.5 max-w-xl text-[14px] leading-relaxed text-slate-300">{description}</p>}
    {children}
  </div>;
}
