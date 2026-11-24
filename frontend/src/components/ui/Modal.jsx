import React, { useEffect, useRef } from 'react';

export default function Modal({ open, onClose, title, children, side = false, className = '' }) {
  const dialogRef = useRef(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement;
    const focusable = () => dialogRef.current?.querySelectorAll('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])') || [];
    focusable()[0]?.focus();
    const onKeyDown = (event) => {
      if (event.key === 'Escape') onCloseRef.current?.();
      if (event.key === 'Tab') {
        const items = [...focusable()];
        if (!items.length) { event.preventDefault(); dialogRef.current?.focus(); return; }
        if (event.shiftKey && document.activeElement === items[0]) { event.preventDefault(); items.at(-1).focus(); }
        else if (!event.shiftKey && document.activeElement === items.at(-1)) { event.preventDefault(); items[0].focus(); }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => { window.removeEventListener('keydown', onKeyDown); previous?.focus?.(); };
  }, [open]);

  if (!open) return null;
  return <div className={`fixed inset-0 z-50 flex ${side ? 'justify-end' : 'items-center justify-center'} bg-black/65 p-3 backdrop-blur-sm`} onMouseDown={(event) => { if (event.target === event.currentTarget) onClose?.(); }}>
    <section ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className={`glass-panel max-h-full w-full ${side ? 'overflow-hidden flex flex-col' : 'overflow-y-auto'} overscroll-contain rounded-2xl ${side ? 'max-w-2xl rounded-r-none' : 'max-w-2xl'} ${className}`}>
      {title && <h2 className="sr-only">{title}</h2>}{children}
    </section>
  </div>;
}
