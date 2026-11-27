export function reconnectDelay(attempt, random = Math.random) {
  const exponent = Math.min(Math.max(0, Number(attempt) || 0), 5);
  const base = Math.min(30000, 1000 * (2 ** exponent));
  const jitter = 0.75 + Math.min(1, Math.max(0, Number(random()) || 0)) * 0.5;
  return Math.min(30000, Math.round(base * jitter));
}
