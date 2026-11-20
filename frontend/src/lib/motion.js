import gsap from 'gsap';

export const motion = Object.freeze({
  ease: 'power3.out',
  easeSoft: 'expo.out',
  duration: { fast: 0.18, base: 0.32, entrance: 0.72 },
  stagger: 0.08,
});

export function prefersReducedMotion() {
  const override = window.localStorage.getItem('cyberguardx_reduce_motion');
  return override === null
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
    : override === 'true';
}

/** Owns responsive and reduced-motion timelines and cleans them up on unmount. */
export function createMotionScope(scope, animate) {
  let media = null;
  const setup = () => {
    media?.revert();
    media = gsap.matchMedia(scope);
    media.add({ reduce: '(prefers-reduced-motion: reduce)', full: '(prefers-reduced-motion: no-preference)' }, (context) => {
      const overridden = window.localStorage.getItem('cyberguardx_reduce_motion');
      const reduced = overridden === null ? context.conditions.reduce : overridden === 'true';
      if (reduced) animate(true);
      else animate(false);
    });
  };
  setup();
  window.addEventListener('cyberguardx-motion-change', setup);
  return () => {
    window.removeEventListener('cyberguardx-motion-change', setup);
    media?.revert();
  };
}
