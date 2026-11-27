import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DataManagement from './DataManagement';

const api = vi.hoisted(() => ({
  getModelsStatus: vi.fn(() => Promise.resolve({ models: {} })),
  getCicidsStatus: vi.fn(() => Promise.resolve(null)),
  getEvaluationResults: vi.fn(() => Promise.resolve({ available: false })),
  getDemoReplayStatus: vi.fn(() => Promise.resolve({ status: 'idle' })),
  uploadLogs: vi.fn(),
  getUploadStatus: vi.fn(),
}));
vi.mock('../services/api', () => ({ api }));
vi.mock('@gsap/react', () => ({ useGSAP: () => {} }));

describe('DataManagement upload feedback', () => {
  it('polls queued large uploads and shows completion results', async () => {
    const user = userEvent.setup();
    api.uploadLogs.mockResolvedValue({ status: 'queued', job_id: 'upload-1', progress: { total_rows: 5200 } });
    api.getUploadStatus.mockResolvedValue({ status: 'completed', progress: { rows_read: 5200, total_rows: 5200 }, result: { message: 'Inserted 5,100 of 5,200 rows.' } });
    render(<DataManagement role="analyst" />);
    const input = await screen.findByLabelText('Click to upload security logs').catch(() => document.getElementById('file-upload'));
    await user.upload(input, new File(['a,b\n1,2'], 'events.csv', { type: 'text/csv' }));
    expect(await screen.findByText('Inserted 5,100 of 5,200 rows.')).toBeTruthy();
    expect(api.getUploadStatus).toHaveBeenCalledWith('upload-1');
  });

  it('exposes the upload control only to analysts and admins', () => {
    render(<DataManagement role="viewer" />);
    expect(document.getElementById('file-upload')).toBeNull();
  });
});
