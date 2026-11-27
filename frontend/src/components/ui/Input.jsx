import React from 'react';
import { cn } from './cn';

const base = 'w-full rounded-[14px] border border-transparent bg-[var(--chip)] px-4 py-3 text-sm text-[var(--ink)] placeholder:text-[var(--subtle)] transition focus:border-transparent focus:outline-none focus:ring-2 focus:ring-[var(--cobalt)]/35';

const Input = React.forwardRef(function Input({ className, ...props }, ref) {
  return <input ref={ref} className={cn(base, className)} {...props} />;
});

export { base as inputClassName };
export default Input;
