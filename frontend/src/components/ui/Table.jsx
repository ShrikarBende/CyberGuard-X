import React from 'react';
import { cn } from './cn';

export function Table({ className, ...props }) { return <div className="overflow-x-auto"><table className={cn('w-full border-collapse text-left text-xs', className)} {...props} /></div>; }
export function TableHeader({ className, ...props }) { return <thead className={cn('border-b border-white/10 text-[10px] font-semibold uppercase tracking-wider text-slate-400', className)} {...props} />; }
export function TableBody({ className, ...props }) { return <tbody className={cn('divide-y divide-white/[0.06] text-slate-300', className)} {...props} />; }
export function TableRow({ className, ...props }) { return <tr className={cn('transition-colors hover:bg-white/[0.035]', className)} {...props} />; }
export function TableCell({ as: Element = 'td', className, ...props }) { return <Element className={cn('px-3 py-3 align-middle', className)} {...props} />; }
