import assert from 'node:assert/strict';
import test from 'node:test';

import type { AuthRequestRecord } from '../src/types';
import { AUTH_REQUEST_EXPIRATION_MS, isAuthRequestExpired } from '../src/services/auth-request-policy';

const BASE: AuthRequestRecord = {
  id: 'ar-1',
  userId: 'u1',
  organizationId: null,
  type: 0,
  requestDeviceIdentifier: 'dev-1',
  requestDeviceType: 14,
  requestIpAddress: null,
  requestCountryName: null,
  responseDeviceIdentifier: null,
  accessCode: 'abc',
  publicKey: 'pub',
  key: null,
  masterPasswordHash: null,
  approved: null,
  creationDate: new Date(1_700_000_000_000).toISOString(),
  responseDate: null,
  authenticationDate: null,
};

function recordAt(nowMs: number): AuthRequestRecord {
  return { ...BASE, creationDate: new Date(nowMs).toISOString() };
}

test('auth-request policy: not expired inside the window', () => {
  const now = 1_700_000_000_000 + AUTH_REQUEST_EXPIRATION_MS - 1;
  assert.equal(isAuthRequestExpired(recordAt(now - AUTH_REQUEST_EXPIRATION_MS + 1), now), false);
});

test('auth-request policy: expired at exactly the window edge', () => {
  const now = 1_700_000_000_000 + AUTH_REQUEST_EXPIRATION_MS;
  assert.equal(isAuthRequestExpired(recordAt(now - AUTH_REQUEST_EXPIRATION_MS), now), true);
});

test('auth-request policy: expired after the window', () => {
  const now = 1_700_000_000_000 + AUTH_REQUEST_EXPIRATION_MS + 1;
  assert.equal(isAuthRequestExpired(recordAt(now - AUTH_REQUEST_EXPIRATION_MS - 1), now), true);
});

test('auth-request policy: window is 15 minutes', () => {
  assert.equal(AUTH_REQUEST_EXPIRATION_MS, 15 * 60 * 1000);
});
