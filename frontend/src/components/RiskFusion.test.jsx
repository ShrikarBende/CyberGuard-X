import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

vi.mock('@gsap/react', () => ({ useGSAP: () => {} }));
vi.mock('gsap', () => ({ gsap: { utils: { toArray: () => [] }, set: vi.fn(), fromTo: vi.fn() } }));
vi.mock('../lib/motion', () => ({
  createMotionScope: () => {},
  motion: { duration: { entrance: 0 }, stagger: 0, ease: 'none', easeSoft: 'none' },
}));

import RiskFusion from './RiskFusion';

describe('RiskFusion label disclosure', () => {
  it('marks TFT, GAT and Fusion evidence as proxy-label validated', () => {
    render(<RiskFusion explanation={{
      calibrated_risk_score: 0.63,
      severity: 'HIGH',
      per_layer_contributions: { user_contribution: 20, endpoint_contribution: 30,
        network_contribution: 35, open_set_contribution: 15 },
    }} />);

    expect(screen.getByText(/proxy-label validated/i)).toBeTruthy();
    expect(screen.getByText(/TFT and GAT validation use heuristic or attack-category proxy labels/i)).toBeTruthy();
    expect(screen.getByText(/do not establish independently labeled real-world incident performance/i)).toBeTruthy();
  });
});
