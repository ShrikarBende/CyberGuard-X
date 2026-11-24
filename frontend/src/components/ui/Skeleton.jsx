import React from 'react';
import { cn } from './cn';

export default function Skeleton({ className, ...props }) {
  return <div aria-hidden="true" className={cn('animate-pulse rounded-xl bg-gradient-to-r from-white/[0.035] via-white/[0.075] to-white/[0.035] motion-reduce:animate-none', className)} {...props} />;
}
