import React from 'react';
import { cn } from './cn';

export default function Glass({ as: Element = 'div', className, strong = false, children, ...props }) {
  return <Element className={cn('glass', strong && 'glass--strong', className)} {...props}>{children}</Element>;
}
