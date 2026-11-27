import React from 'react';
import { cn } from './cn';

export function Table({ className, ...props }) { return <div className="overflow-x-auto rounded-[var(--r-inner)] bg-[var(--card)]"><table className={cn('soc-table w-full border-collapse text-left text-sm', className)} {...props} /></div>; }
export function TableHeader({ className, ...props }) { return <thead className={cn('sticky top-0 z-10 bg-[var(--card)] text-left text-xs font-medium text-[var(--muted)]', className)} {...props} />; }
export function TableBody({ className, ...props }) { return <tbody className={cn('text-[var(--ink)]', className)} {...props} />; }
export function TableRow({ className, ...props }) { return <tr className={cn('soc-table-row transition-colors duration-200', className)} {...props} />; }
export function TableCell({ as: Element = 'td', className, ...props }) { return <Element className={cn('px-3 py-3 align-middle', className)} {...props} />; }
