import React, { useRef } from 'react';
import { ArrowRight, ShieldCheck } from '../lib/icons';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';

export default function LoginScreen({ loginName, setLoginName, loginPassword, setLoginPassword, loginError, loginPending, handleLogin }) {
  const root = useRef(null);
  useGSAP(() => {
    const cleanup = createMotionScope(root.current, (reduced) => {
      const duration = reduced ? 0.2 : motion.duration.entrance;
      const tl = gsap.timeline({ defaults: { ease: motion.ease, duration } });
      tl.fromTo('.login-copy', { autoAlpha: 0, y: reduced ? 0 : 16 }, { autoAlpha: 1, y: 0 })
        .fromTo('.login-form', { autoAlpha: 0, y: reduced ? 0 : 12 }, { autoAlpha: 1, y: 0 }, '-=0.4');
    });
    return cleanup;
  }, { scope: root });

  useGSAP(() => {
    if (!loginError) return undefined;
    return createMotionScope(root.current, (reduced) => {
      if (reduced) gsap.fromTo('.login-form', { autoAlpha: 0.8 }, { autoAlpha: 1, duration: 0.18 });
      else gsap.fromTo('.login-form', { x: -5 }, { x: 0, duration: 0.28, ease: 'elastic.out(1, 0.35)' });
    });
  }, { scope: root, dependencies: [loginError], revertOnUpdate: true });

  const magnet = (event) => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.localStorage.getItem('cyberguardx_reduce_motion') === 'true') return;
    const bounds = event.currentTarget.getBoundingClientRect();
    gsap.to(event.currentTarget, { x: (event.clientX - bounds.left - bounds.width / 2) * 0.08, y: (event.clientY - bounds.top - bounds.height / 2) * 0.12, duration: 0.22, ease: 'power2.out' });
  };

  return <main ref={root} className="flex min-h-[100dvh] items-center justify-center px-4 py-4 sm:px-6 sm:py-8">
    <div className="grid w-full max-w-[1160px] items-stretch gap-3 md:grid-cols-[1.2fr_1fr]">
      <section className="login-copy login-hero-card flex min-h-24 flex-col justify-between rounded-[var(--r-card)] bg-[var(--cobalt)] p-5 text-white md:min-h-[560px] md:p-10">
        <div className="flex items-center gap-3"><ShieldCheck className="h-5 w-5 text-white" /><p className="font-display text-xl font-extrabold text-white">CyberGuard X</p></div>
        <div className="hidden md:block"><h1 className="login-hero-title font-display text-[54px] font-bold leading-[1.05] tracking-[-.045em] text-white lg:text-[64px]">See the signal.<br />Secure what matters.</h1><p className="mt-6 text-sm text-white/75">Enterprise security operations</p></div>
        <p className="text-sm text-white/80 md:hidden">Enterprise security operations</p>
      </section>
      <form onSubmit={handleLogin} className="login-form glass mx-auto w-full max-w-xl rounded-[var(--r-card)] p-6 sm:p-8 md:my-auto">
        <div className="mb-7"><p className="text-xs font-medium text-[var(--muted)]">Analyst access</p><h1 className="mt-2 font-display text-3xl font-bold leading-tight tracking-tight text-[var(--ink)]">Analyst sign in</h1><p className="mt-2 text-sm text-[var(--muted)]">Sign in with your assigned analyst account.</p></div>
        {loginError && <p role="alert" className="mb-4 rounded-xl bg-[var(--critical-tint)] p-3 text-sm text-[var(--critical)]">{loginError}</p>}
        <label className="mb-4 block text-xs font-medium text-[var(--muted)]">Username<input value={loginName} onChange={(event) => setLoginName(event.target.value)} autoComplete="username" required className="mt-2 w-full rounded-[14px] border border-[#C9CFDD] bg-[#E9ECF4] px-4 py-3 text-sm text-[var(--ink)] placeholder:text-[var(--subtle)] focus:border-[var(--cobalt)] focus:outline-none focus:ring-2 focus:ring-[var(--cobalt)]/35" /></label>
        <label className="mb-6 block text-xs font-medium text-[var(--muted)]">Password<input type="password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} autoComplete="current-password" required className="mt-2 w-full rounded-[14px] border border-[#C9CFDD] bg-[#E9ECF4] px-4 py-3 text-sm text-[var(--ink)] placeholder:text-[var(--subtle)] focus:border-[var(--cobalt)] focus:outline-none focus:ring-2 focus:ring-[var(--cobalt)]/35" /></label>
        <button onMouseMove={magnet} onMouseLeave={(event) => gsap.to(event.currentTarget, { x: 0, y: 0, duration: 0.3 })} disabled={loginPending} className="soc-primary-button group flex w-full items-center justify-center gap-2 rounded-full bg-[var(--cobalt)] px-4 py-3 text-sm font-semibold text-white transition hover:bg-[var(--cobalt-hover)] disabled:opacity-50">{loginPending ? 'Signing in…' : 'Sign in'}{!loginPending && <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />}</button>
      </form>
    </div>
  </main>;
}
