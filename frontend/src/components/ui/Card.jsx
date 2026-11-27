import React from 'react';
import { cn } from './cn';

export default function Card({ as: Element = 'section', className, children, ...props }) {
  return <Element className={cn('soc-card rounded-[var(--r-card)] p-[var(--soc-space-card)]', className)} {...props}>{children}</Element>;
}
