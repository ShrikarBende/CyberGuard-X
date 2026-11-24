import gsap from 'gsap';
import { CustomEase } from 'gsap/CustomEase';

gsap.registerPlugin(CustomEase);

const premiumEase = CustomEase.create('cyberguard-premium', 'M0,0 C0.22,1 0.36,1 1,1');

export const motion = Object.freeze({
  ease: premiumEase,
  easeSoft: premiumEase,
  duration: { fast: 0.3, base: 0.5, entrance: 0.72 },
  stagger: 0.06,
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
  const targetScope = scope?.current || scope?.nativeElement || scope;
  if (!targetScope || typeof targetScope.querySelectorAll !== 'function') return () => {};

  const setup = () => {
    media?.revert();
    media = gsap.matchMedia();
    media.add({ reduce: '(prefers-reduced-motion: reduce)', full: '(prefers-reduced-motion: no-preference)' }, (context) => {
      const overridden = window.localStorage.getItem('cyberguardx_reduce_motion');
      const reduced = overridden === null ? context.conditions.reduce : overridden === 'true';
      if (reduced) animate(true);
      else animate(false);
    }, targetScope);
  };
  setup();
  window.addEventListener('cyberguardx-motion-change', setup);
  return () => {
    window.removeEventListener('cyberguardx-motion-change', setup);
    media?.revert();
  };
}
