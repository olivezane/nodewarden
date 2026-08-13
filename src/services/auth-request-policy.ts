import type { AuthRequestRecord } from '../types';

// Auth-request expiry policy. Persistence and handlers both depend on this
// module; the window is defined exactly once.
export const AUTH_REQUEST_EXPIRATION_MS = 15 * 60 * 1000;

export function isAuthRequestExpired(request: AuthRequestRecord, nowMs: number = Date.now()): boolean {
  return new Date(request.creationDate).getTime() + AUTH_REQUEST_EXPIRATION_MS <= nowMs;
}
