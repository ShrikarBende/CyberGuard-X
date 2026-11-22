import React from 'react';
import { cn } from './cn';

export default function GlassCard({ as: Element = 'section', className, children, ...props }) {
  return <Element className={cn('soc-card glass-card rounded-[22px] p-[var(--soc-space-card)]', className)} {...props}>{children}</Element>;
}
