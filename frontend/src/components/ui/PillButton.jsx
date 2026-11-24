import React from 'react';
import Button from './Button';
import { cn } from './cn';

export default function PillButton({ variant = 'secondary', className, ...props }) {
  return <Button variant={variant === 'secondary' ? 'ghost' : variant} className={cn('rounded-full', className)} {...props} />;
}
