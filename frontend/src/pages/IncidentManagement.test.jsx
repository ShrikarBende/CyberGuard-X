import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import IncidentManagement from './IncidentManagement';

const api = vi.hoisted(() => ({
  getIncidents: vi.fn(() => Promise.resolve([{
    incident_id: 'incident-test-1', title: 'Test incident', description: 'Review this event.',
    severity: 'HIGH', status: 'OPEN', overall_risk_score: 72, flow_count: 1,
  }])),
  getAgentConfig: vi.fn(() => Promise.resolve({ enabled: false })),
  updateIncidentStatus: vi.fn(() => Promise.resolve({ status: 'INVESTIGATING' })),
}));
vi.mock('../services/api', () => ({ api }));
vi.mock('@gsap/react', () => ({ useGSAP: () => {} }));

describe('IncidentManagement workflow', () => {
  it('lets analysts update incident status and confirms the action', async () => {
    const user = userEvent.setup();
    render(<IncidentManagement role="analyst" />);
    const status = await screen.findByRole('combobox', { name: 'Incident status' });
    await user.selectOptions(status, 'INVESTIGATING');
    await waitFor(() => expect(api.updateIncidentStatus).toHaveBeenCalledWith('incident-test-1', 'INVESTIGATING'));
    expect(await screen.findByText('Incident status updated.')).toBeTruthy();
  });

  it('does not show status controls to viewers', async () => {
    render(<IncidentManagement role="viewer" />);
    await screen.findAllByText('Test incident');
    expect(screen.queryByRole('combobox', { name: 'Incident status' })).toBeNull();
  });
});
