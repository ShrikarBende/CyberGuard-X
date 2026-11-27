import { describe, expect, it } from 'vitest';
import { reconnectDelay } from './reconnect';

describe('reconnectDelay', () => {
  it('backs off between retries and applies bounded jitter', () => {
    expect(reconnectDelay(0, () => 0)).toBe(750);
    expect(reconnectDelay(1, () => 0.5)).toBe(2000);
    expect(reconnectDelay(2, () => 1)).toBe(5000);
  });

  it('caps the retry interval and clamps invalid attempts', () => {
    expect(reconnectDelay(100, () => 1)).toBe(30000);
    expect(reconnectDelay(-2, () => 0.5)).toBe(1000);
  });
});
