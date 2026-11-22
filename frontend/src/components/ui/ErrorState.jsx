import React from 'react';
import { cn } from './cn';

export default function ErrorState({ title = 'Something went wrong', description, onRetry, className }) {
  return <section role="alert" className={cn('rounded-[22px] border border-rose-300/20 bg-gradient-to-b from-rose-400/[0.07] to-transparent p-5 text-rose-100', className)}>
    <h3 className="text-[15px] font-medium">{title}</h3>
    {description && <p className="mt-1 text-[14px] text-rose-100/80">{description}</p>}
    {onRetry && <button type="button" onClick={onRetry} className="mt-4 rounded-full border border-white/15 bg-white/[0.04] px-4 py-2 text-[14px] hover:bg-white/[0.08]">Try again</button>}
  </section>;
}
