# Motion and design notes

## Design tokens

`src/index.css` defines the SOC palette, layered surfaces, radii, shadows, spacing, and font stacks as CSS custom properties. Tailwind maps the semantic `soc` colors and display, body, and mono font families to those variables in `tailwind.config.js`. Use the semantic severity colors consistently: critical, high, medium, low, normal, and novel. The locally bundled fonts are Space Grotesk Variable for headings, Inter Variable for body text, and JetBrains Mono for IDs and telemetry values.

`src/components/ui/` contains small, logic-free building blocks. `Card`, `StatTile`, `Badge`, `Button`, `Input`, `Skeleton`, `EmptyState`, `Tooltip`, `Modal`, `SectionHeader`, and table primitives accept their normal content and styling props. Page components remain responsible for data and behavior.

`src/charts/` provides a shared Recharts tooltip and a compact palette/axis theme. Keep chart data sourced from the existing API and pass no generated placeholder data.

## Motion helpers

`src/lib/motion.js` exports the shared easing and duration values, `prefersReducedMotion()`, and `createMotionScope(scope, animate)`. Use the `useGSAP` hook from `@gsap/react` in components that create animations. Scope selectors to a component ref and return the cleanup from `createMotionScope`; its media context is reverted on unmount and when the motion preference changes.

Animate opacity and transforms only. Keep live telemetry animation limited to the new row. For chart entrance effects, use Recharts animation props and gate them with `prefersReducedMotion()`.

## Adding an animated component

1. Add a root ref to the component.
2. Call `useGSAP` with that ref as the scope.
3. Inside the callback, return `createMotionScope(ref.current, (reduced) => { ... })`.
4. Use a short fade when `reduced` is true; otherwise use a restrained opacity/transform timeline.
5. Add `revertOnUpdate: true` when the animation depends on changing props or state.

The login screen, shell, page content, Overview, live-event rows, and RiskFusion contribution bars are current examples.

## Disabling motion

The header's **Reduce motion** control stores an explicit override in `localStorage` under `cyberguardx_reduce_motion` and refreshes active scoped animations. With no override, the operating system's `prefers-reduced-motion` setting is used. CSS also shortens transitions and keyframe animations for the reduced-motion state.

## Verification

Run `npm ci && npm run build` from `frontend/`. The build remains self-hosted: font assets are imported from `@fontsource` packages and no remote scripts or font URLs are required.

GSAP references: [React integration](https://gsap.com/resources/React/) and [gsap.matchMedia()](https://gsap.com/docs/v3/GSAP/gsap.matchMedia/).
