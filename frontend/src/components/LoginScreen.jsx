import React, { useRef } from 'react';
import { Activity, ArrowRight, ShieldCheck } from 'lucide-react';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';

export default function LoginScreen({ loginName, setLoginName, loginPassword, setLoginPassword, loginError, loginPending, handleLogin }) {
  const root = useRef(null);
  useGSAP(() => {
    const cleanup = createMotionScope(root.current, (reduced) => {
      const duration = reduced ? 0.2 : motion.duration.entrance;
      const tl = gsap.timeline({ defaults: { ease: motion.ease, duration } });
      tl.fromTo('.login-orbit', { autoAlpha: 0, scale: 0.9 }, { autoAlpha: 1, scale: 1 })
        .fromTo('.login-copy', { autoAlpha: 0, y: reduced ? 0 : 16 }, { autoAlpha: 1, y: 0 }, '-=0.48')
        .fromTo('.login-form', { autoAlpha: 0, y: reduced ? 0 : 12 }, { autoAlpha: 1, y: 0 }, '-=0.4');
      if (!reduced) gsap.to('.radar-sweep', { rotation: 360, duration: 24, ease: 'none', repeat: -1 });
    });
    return cleanup;
  }, { scope: root });

  useGSAP(() => {
    if (loginError) gsap.fromTo('.login-form', { x: -5 }, { x: 0, duration: 0.28, ease: 'elastic.out(1, 0.35)' });
  }, { scope: root, dependencies: [loginError], revertOnUpdate: true });

  const magnet = (event) => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.localStorage.getItem('cyberguardx_reduce_motion') === 'true') return;
    const bounds = event.currentTarget.getBoundingClientRect();
    gsap.to(event.currentTarget, { x: (event.clientX - bounds.left - bounds.width / 2) * 0.08, y: (event.clientY - bounds.top - bounds.height / 2) * 0.12, duration: 0.22, ease: 'power2.out' });
  };

  return <main ref={root} className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#080d18] px-5 py-10 text-slate-100">
    <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_58%_48%,rgba(49,100,196,0.16),transparent_54%)]" />
    <div className="login-orbit pointer-events-none absolute right-[8%] top-1/2 hidden aspect-square w-[min(54vw,680px)] -translate-y-1/2 rounded-full border border-blue-300/[0.12] md:block">
      <div className="absolute inset-[12%] rounded-full border border-blue-300/[0.09]" /><div className="absolute inset-[27%] rounded-full border border-violet-300/[0.09]" />
      <div className="radar-sweep absolute inset-0 rounded-full bg-[conic-gradient(from_0deg,transparent_0deg,rgba(59,130,246,0.12)_34deg,transparent_70deg)]" />
      <span className="absolute left-1/2 top-0 h-full border-l border-blue-300/[0.06]" /><span className="absolute left-0 top-1/2 w-full border-t border-blue-300/[0.06]" />
      <span className="absolute left-[21%] top-[33%] h-1.5 w-1.5 rounded-full bg-blue-300 shadow-[0_0_14px_4px_rgba(96,165,250,0.45)]" />
      <span className="absolute right-[24%] top-[62%] h-1.5 w-1.5 rounded-full bg-violet-300 shadow-[0_0_14px_4px_rgba(192,132,252,0.4)]" />
    </div>
    <div className="relative z-10 grid w-full max-w-6xl items-center gap-14 md:grid-cols-[1fr_420px]">
      <section className="login-copy hidden max-w-xl md:block">
        <div className="mb-8 inline-flex items-center gap-3"><div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-blue-300/20 bg-blue-400/10 text-blue-200"><ShieldCheck className="h-5 w-5" /></div><div><p className="font-display text-sm font-bold tracking-wide">CyberGuard X</p><p className="soc-mono text-[10px] uppercase tracking-[0.2em] text-blue-300">Enterprise Security Operations</p></div></div>
        <p className="soc-mono mb-4 flex items-center gap-2 text-[10px] uppercase tracking-[0.22em] text-emerald-300"><Activity className="h-3.5 w-3.5" /> Continuous behavioral analysis</p>
        <h1 className="font-display text-5xl font-semibold leading-[1.08] tracking-tight text-white lg:text-6xl">See the signal.<br /><span className="bg-gradient-to-r from-blue-300 to-violet-300 bg-clip-text text-transparent">Secure what matters.</span></h1>
        <p className="mt-6 max-w-md text-sm leading-7 text-slate-400">A unified view of identity, endpoint, and network risk for your security operations team.</p>
      </section>
      <form onSubmit={handleLogin} className="login-form glass-panel mx-auto w-full max-w-md rounded-3xl p-7 sm:p-9">
        <div className="mb-7 md:hidden"><div className="mb-5 flex h-10 w-10 items-center justify-center rounded-xl border border-blue-300/20 bg-blue-400/10 text-blue-200"><ShieldCheck className="h-5 w-5" /></div><h1 className="font-display text-2xl font-semibold tracking-tight">CyberGuard X</h1><p className="mt-2 text-xs text-slate-400">Enterprise Security Operations</p></div>
        <div className="mb-7"><p className="soc-mono text-[10px] uppercase tracking-[0.18em] text-blue-300">Analyst access</p><h2 className="mt-2 font-display text-2xl font-semibold text-white">CyberGuard X analyst sign in</h2><p className="mt-2 text-xs leading-5 text-slate-400">Sign in with your assigned analyst account.</p></div>
        {loginError && <p role="alert" className="mb-4 rounded-xl border border-rose-400/25 bg-rose-400/10 p-3 text-xs text-rose-200">{loginError}</p>}
        <label className="mb-4 block text-xs font-medium text-slate-300">Username<input value={loginName} onChange={(event) => setLoginName(event.target.value)} autoComplete="username" required className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/50 px-3.5 py-3 text-sm text-white placeholder:text-slate-600 focus:border-blue-400/70 focus:outline-none focus:ring-2 focus:ring-blue-400/15" /></label>
        <label className="mb-6 block text-xs font-medium text-slate-300">Password<input type="password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} autoComplete="current-password" required className="mt-2 w-full rounded-xl border border-white/10 bg-slate-950/50 px-3.5 py-3 text-sm text-white placeholder:text-slate-600 focus:border-blue-400/70 focus:outline-none focus:ring-2 focus:ring-blue-400/15" /></label>
        <button onMouseMove={magnet} onMouseLeave={(event) => gsap.to(event.currentTarget, { x: 0, y: 0, duration: 0.3 })} disabled={loginPending} className="group flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-500 to-violet-500 px-4 py-3.5 text-sm font-semibold text-white shadow-lg shadow-blue-950/40 transition-[filter,transform] hover:brightness-110 active:scale-[0.99] disabled:opacity-50">{loginPending ? 'Signing in…' : 'Sign in'}{!loginPending && <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />}</button>
        <p className="mt-5 text-center text-[10px] leading-relaxed text-slate-500">Sign in with your assigned analyst account.</p>
      </form>
    </div>
  </main>;
}
