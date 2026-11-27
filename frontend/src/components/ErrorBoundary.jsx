import React from 'react';

export default class ErrorBoundary extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('Page content failed to render:', error, info);
  }

  componentDidUpdate(previousProps) {
    if (this.state.error && previousProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render() {
    const { error } = this.state;
    if (error) {
      const showDetails = import.meta.env?.DEV === true;
      return (
        <section className="mx-auto mt-8 w-full max-w-2xl rounded-2xl border border-white/10 bg-slate-900 p-6 text-slate-200 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]" role="alert">
          <h2 className="font-display text-lg font-semibold text-slate-100">This page hit an error</h2>
          {showDetails && <pre className="mt-3 overflow-auto whitespace-pre-wrap break-words font-mono text-sm text-rose-200">{String(error.message || error)}</pre>}
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="mt-5 rounded-lg border border-white/10 bg-white/[0.05] px-4 py-2 text-sm font-medium text-slate-100 transition hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          >
            Try again
          </button>
          <p className="mt-4 text-xs text-slate-400">{showDetails ? 'Open the console for more details.' : 'The issue was recorded for diagnosis. You can try again or reload the page.'}</p>
        </section>
      );
    }
    return this.props.children;
  }
}
