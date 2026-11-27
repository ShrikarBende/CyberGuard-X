import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

const api = vi.hoisted(() => ({
  getCurrentAnalyst: vi.fn(() => Promise.resolve({ username: 'reviewer', role: 'analyst' })),
  getDemoStatus: vi.fn(() => Promise.resolve({ has_synthetic_demo: false })),
}));

vi.mock('./services/api', () => ({ api }));
vi.mock('@gsap/react', () => ({ useGSAP: () => {} }));
vi.mock('./components/Sidebar', () => ({ default: () => <nav>Navigation</nav> }));
vi.mock('./components/Header', () => ({ default: ({ pageTitle }) => <header>{pageTitle}</header> }));
vi.mock('./components/ui/Modal', () => ({ default: () => null }));
vi.mock('./pages/Overview', () => ({ default: () => <h1>Overview mounted</h1> }));

describe('App startup', () => {
  it('renders the authenticated dashboard shell without runtime reference errors', async () => {
    window.sessionStorage.setItem('cyberguardx_access_token', 'test-token');
    window.sessionStorage.setItem('cyberguardx_analyst', '{"username":"reviewer","role":"analyst"}');
    window.location.hash = '#overview';
    render(<App />);
    expect(await screen.findByText('Overview mounted')).toBeTruthy();
    expect(screen.getByText('Executive Overview Dashboard')).toBeTruthy();
  });
});
