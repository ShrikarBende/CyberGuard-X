import React from 'react';
import { cn } from './cn';

const base = 'w-full rounded-xl border border-white/10 bg-slate-950/45 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 transition focus:border-blue-400/60 focus:outline-none focus:ring-2 focus:ring-blue-400/20';

const Input = React.forwardRef(function Input({ className, ...props }, ref) {
  return <input ref={ref} className={cn(base, className)} {...props} />;
});

export { base as inputClassName };
export default Input;
