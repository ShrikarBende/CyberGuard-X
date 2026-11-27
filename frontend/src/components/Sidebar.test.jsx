import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Sidebar from './Sidebar';

vi.mock('../services/api', () => ({ api: { getDashboardStats: vi.fn(() => new Promise(() => {})) } }));

describe('Sidebar role and keyboard access', () => {
  it('hides the assistant from viewer navigation and supports arrow navigation', async () => {
    const user = userEvent.setup();
    render(<Sidebar role="viewer" activePage="overview" setActivePage={() => {}} />);
    const nav = screen.getByRole('navigation', { name: 'Primary navigation' });
    expect(screen.queryByRole('button', { name: 'AI Security Assistant' })).toBeNull();
    const overview = screen.getByRole('button', { name: 'Overview Dashboard' });
    overview.focus();
    await user.keyboard('{ArrowDown}');
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Live Monitoring' }));
    expect(nav).not.toBeNull();
  });
});
