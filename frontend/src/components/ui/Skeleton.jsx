import React from 'react';
import { cn } from './cn';

export default function Skeleton({ className, ...props }) {
  return <div aria-hidden="true" className={cn('animate-pulse rounded-lg bg-white/[0.07]', className)} {...props} />;
}
