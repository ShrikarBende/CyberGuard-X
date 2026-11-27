import React from 'react';
import { cn } from './cn';

export default function Skeleton({ className, ...props }) {
  return <div aria-hidden="true" className={cn('soc-skeleton rounded-xl', className)} {...props} />;
}
