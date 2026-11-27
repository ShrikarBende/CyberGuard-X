import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';

describe('API session handling', () => {
  beforeEach(() => {
    window.sessionStorage.setItem('cyberguardx_access_token', 'expired-token');
    window.sessionStorage.setItem('cyberguardx_analyst', '{"username":"analyst"}');
  });

  it('clears expired credentials and announces session expiry', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ detail: 'A valid analyst bearer token is required.' }),
    });
    const expired = vi.fn();
    window.addEventListener('analyst-session-expired', expired);
    try {
      await expect(api.getCurrentAnalyst()).rejects.toThrow('A valid analyst bearer token is required.');
      expect(window.sessionStorage.getItem('cyberguardx_access_token')).toBeNull();
      expect(window.sessionStorage.getItem('cyberguardx_analyst')).toBeNull();
      expect(expired).toHaveBeenCalledOnce();
      expect(fetchSpy).toHaveBeenCalledOnce();
    } finally {
      window.removeEventListener('analyst-session-expired', expired);
    }
  });
});
