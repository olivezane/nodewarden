import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env } from '../src/types';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  createJWT,
  createSendAccessToken,
  createSendFileDownloadToken,
  createSendFileUploadToken,
  signJwt,
  verifyJwt,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
  verifyJWT,
  verifySendAccessToken,
  verifySendFileDownloadToken,
  verifySendFileUploadToken,
} from '../src/utils/jwt';
import type { UserVerificationPurpose } from '../src/utils/user-verification-token';
import {
  createPasskeyUserVerificationToken,
  createTotpUserVerificationToken,
  verifyPasskeyUserVerificationToken,
  verifyTotpUserVerificationToken,
} from '../src/utils/user-verification-token';
import {
  createAccountPasskeyToken,
  verifyAccountPasskeyToken,
} from '../src/utils/account-passkeys';

const SECRET = 'token-security-test-secret-0123456789abcdef';
const OTHER_SECRET = 'another-test-secret-0123456789abcdef';
const env = { JWT_SECRET: SECRET } as unknown as Env;

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

function tamperPart(token: string, index: number): string {
  const parts = token.split('.');
  const part = parts[index];
  const flipped = part[0] === 'a' ? 'b' : 'a';
  parts[index] = flipped + part.slice(1);
  return parts.join('.');
}

// ---------------------------------------------------------------------------
// Access token (createJWT / verifyJWT)
// ---------------------------------------------------------------------------

test('access token: round-trip preserves claims', async () => {
  const token = await createJWT({ sub: 'u1', email: 'a@b.test', name: 'A', sstamp: 's1', did: 'd1', dstamp: 'd2' }, SECRET);
  const payload = await verifyJWT(token, SECRET);
  assert.ok(payload);
  assert.equal(payload.sub, 'u1');
  assert.equal(payload.email, 'a@b.test');
  assert.equal(payload.name, 'A');
  assert.equal(payload.sstamp, 's1');
  assert.equal(payload.did, 'd1');
  assert.equal(payload.dstamp, 'd2');
  assert.equal(payload.iss, 'nodewarden');
  assert.equal(payload.premium, true);
  assert.equal(payload.email_verified, true);
  assert.deepEqual(payload.amr, ['Application']);
  assert.equal(payload.exp - payload.iat, 7200);
});

test('access token: custom expiry is honored', async () => {
  const token = await createJWT({ sub: 'u1', email: 'a@b.test', name: null, sstamp: 's1' }, SECRET, 60);
  const payload = await verifyJWT(token, SECRET);
  assert.ok(payload);
  assert.equal(payload.exp - payload.iat, 60);
});

test('access token: expired rejected', async () => {
  const token = await signJwt({
    sub: 'u1', email: 'a@b.test', name: null, sstamp: 's1',
    iat: nowSeconds() - 100, exp: nowSeconds() - 1, iss: 'nodewarden', premium: true,
    email_verified: true, amr: ['Application'],
  }, SECRET);
  assert.equal(await verifyJWT(token, SECRET), null);
});

test('access token: wrong secret rejected', async () => {
  const token = await createJWT({ sub: 'u1', email: 'a@b.test', name: null, sstamp: 's1' }, SECRET);
  assert.equal(await verifyJWT(token, OTHER_SECRET), null);
});

test('access token: malformed tokens rejected', async () => {
  assert.equal(await verifyJWT('', SECRET), null);
  assert.equal(await verifyJWT('a.b', SECRET), null);
  assert.equal(await verifyJWT('a.b.c.d', SECRET), null);
  assert.equal(await verifyJWT('not-a-jwt', SECRET), null);
});

test('access token: tampered payload and signature rejected', async () => {
  const token = await createJWT({ sub: 'u1', email: 'a@b.test', name: null, sstamp: 's1' }, SECRET);
  assert.equal(await verifyJWT(tamperPart(token, 1), SECRET), null);
  assert.equal(await verifyJWT(tamperPart(token, 2), SECRET), null);
});

// ---------------------------------------------------------------------------
// File download token
// ---------------------------------------------------------------------------

test('file download token: round-trip', async () => {
  const token = await createFileDownloadToken('c1', 'a1', SECRET);
  const claims = await verifyFileDownloadToken(token, SECRET);
  assert.ok(claims);
  assert.equal(claims.cipherId, 'c1');
  assert.equal(claims.attachmentId, 'a1');
  assert.ok(claims.jti);
  assert.ok(claims.exp > nowSeconds());
});

test('file download token: expired rejected', async () => {
  const token = await signJwt({ cipherId: 'c1', attachmentId: 'a1', jti: 'j', exp: nowSeconds() - 1 }, SECRET);
  assert.equal(await verifyFileDownloadToken(token, SECRET), null);
});

test('file download token: tampered payload and signature rejected', async () => {
  const token = await createFileDownloadToken('c1', 'a1', SECRET);
  assert.equal(await verifyFileDownloadToken(tamperPart(token, 1), SECRET), null);
  assert.equal(await verifyFileDownloadToken(tamperPart(token, 2), SECRET), null);
});

test('file download token: only expiry is validated today (claim leniency pinned)', async () => {
  // Current behavior: this verifier checks expiry only, not claims. Pinned so a
  // future hardening of this verifier shows up as a test change.
  const token = await signJwt({ exp: nowSeconds() + 300 }, SECRET);
  assert.ok(await verifyFileDownloadToken(token, SECRET));
});

// ---------------------------------------------------------------------------
// Attachment upload token
// ---------------------------------------------------------------------------

test('attachment upload token: round-trip', async () => {
  const token = await createAttachmentUploadToken('u1', 'c1', 'a1', SECRET);
  const claims = await verifyAttachmentUploadToken(token, SECRET);
  assert.ok(claims);
  assert.equal(claims.userId, 'u1');
  assert.equal(claims.cipherId, 'c1');
  assert.equal(claims.attachmentId, 'a1');
});

test('attachment upload token: missing claims rejected', async () => {
  const future = nowSeconds() + 300;
  assert.equal(await verifyAttachmentUploadToken(await signJwt({ cipherId: 'c1', attachmentId: 'a1', exp: future }, SECRET), SECRET), null);
  assert.equal(await verifyAttachmentUploadToken(await signJwt({ userId: 'u1', attachmentId: 'a1', exp: future }, SECRET), SECRET), null);
  assert.equal(await verifyAttachmentUploadToken(await signJwt({ userId: 'u1', cipherId: 'c1', exp: future }, SECRET), SECRET), null);
});

test('attachment upload token: expired rejected', async () => {
  const token = await signJwt({ userId: 'u1', cipherId: 'c1', attachmentId: 'a1', exp: nowSeconds() - 1 }, SECRET);
  assert.equal(await verifyAttachmentUploadToken(token, SECRET), null);
});

// ---------------------------------------------------------------------------
// Send file download token
// ---------------------------------------------------------------------------

test('send file download token: round-trip', async () => {
  const token = await createSendFileDownloadToken('s1', 'f1', SECRET);
  const claims = await verifySendFileDownloadToken(token, SECRET);
  assert.ok(claims);
  assert.equal(claims.sendId, 's1');
  assert.equal(claims.fileId, 'f1');
  assert.ok(claims.jti);
});

test('send file download token: missing or mistyped claims rejected', async () => {
  const future = nowSeconds() + 300;
  assert.equal(await verifySendFileDownloadToken(await signJwt({ sendId: 's1', fileId: 'f1', jti: '', exp: future }, SECRET), SECRET), null);
  assert.equal(await verifySendFileDownloadToken(await signJwt({ sendId: 's1', fileId: 'f1', jti: 123, exp: future }, SECRET), SECRET), null);
  assert.equal(await verifySendFileDownloadToken(await signJwt({ sendId: 's1', fileId: 123, jti: 'j', exp: future }, SECRET), SECRET), null);
  assert.equal(await verifySendFileDownloadToken(await signJwt({ sendId: 's1', fileId: 'f1', jti: 'j', exp: 'future' }, SECRET), SECRET), null);
});

test('send file download token: expired rejected', async () => {
  const token = await signJwt({ sendId: 's1', fileId: 'f1', jti: 'j', exp: nowSeconds() - 1 }, SECRET);
  assert.equal(await verifySendFileDownloadToken(token, SECRET), null);
});

// ---------------------------------------------------------------------------
// Send file upload token
// ---------------------------------------------------------------------------

test('send file upload token: round-trip', async () => {
  const token = await createSendFileUploadToken('u1', 's1', 'f1', SECRET);
  const claims = await verifySendFileUploadToken(token, SECRET);
  assert.ok(claims);
  assert.equal(claims.userId, 'u1');
  assert.equal(claims.sendId, 's1');
  assert.equal(claims.fileId, 'f1');
});

test('send file upload token: missing claims rejected', async () => {
  const future = nowSeconds() + 300;
  assert.equal(await verifySendFileUploadToken(await signJwt({ userId: 'u1', fileId: 'f1', exp: future }, SECRET), SECRET), null);
  assert.equal(await verifySendFileUploadToken(await signJwt({ userId: 'u1', sendId: 's1', exp: future }, SECRET), SECRET), null);
});

test('send file upload token: expired rejected', async () => {
  const token = await signJwt({ userId: 'u1', sendId: 's1', fileId: 'f1', exp: nowSeconds() - 1 }, SECRET);
  assert.equal(await verifySendFileUploadToken(token, SECRET), null);
});

// ---------------------------------------------------------------------------
// Send access token
// ---------------------------------------------------------------------------

test('send access token: round-trip', async () => {
  const token = await createSendAccessToken('s1', SECRET);
  const claims = await verifySendAccessToken(token, SECRET);
  assert.ok(claims);
  assert.equal(claims.sub, 's1');
  assert.equal(claims.typ, 'send_access');
  assert.equal(claims.exp - claims.iat, 300);
});

test('send access token: wrong typ rejected', async () => {
  const now = nowSeconds();
  const token = await signJwt({ sub: 's1', typ: 'other', iat: now, exp: now + 300 }, SECRET);
  assert.equal(await verifySendAccessToken(token, SECRET), null);
});

test('send access token: missing sub rejected', async () => {
  const now = nowSeconds();
  const token = await signJwt({ sub: '', typ: 'send_access', iat: now, exp: now + 300 }, SECRET);
  assert.equal(await verifySendAccessToken(token, SECRET), null);
});

test('send access token: expired rejected', async () => {
  const now = nowSeconds();
  const token = await signJwt({ sub: 's1', typ: 'send_access', iat: now - 400, exp: now - 100 }, SECRET);
  assert.equal(await verifySendAccessToken(token, SECRET), null);
});

// ---------------------------------------------------------------------------
// Passkey user-verification token (millisecond expiry)
// ---------------------------------------------------------------------------

test('user verification token: round-trip', async () => {
  const token = await createPasskeyUserVerificationToken(env, 'u1', 'backup.settings.repair');
  assert.equal(await verifyPasskeyUserVerificationToken(env, token, 'u1', 'backup.settings.repair'), true);

  // Token carries a 5-minute lifetime, iat/exp in milliseconds.
  const claims = await verifyJwt<{ typ: string; iat: number; exp: number }>(token, SECRET, () => true);
  assert.ok(claims);
  assert.equal(claims.typ, 'nodewarden.user-verification.v1');
  assert.equal(claims.exp - claims.iat, 5 * 60 * 1000);
});

test('user verification token: wrong typ rejected', async () => {
  const now = Date.now();
  const token = await signJwt({
    typ: 'nodewarden.something-else',
    userId: 'u1',
    method: 'passkey',
    purpose: 'backup.settings.repair',
    iat: now,
    exp: now + 60_000,
  }, SECRET);
  assert.equal(await verifyPasskeyUserVerificationToken(env, token, 'u1', 'backup.settings.repair'), false);
});

test('user verification token: wrong user, purpose, or method rejected', async () => {
  const now = Date.now();
  const base = { typ: 'nodewarden.user-verification.v1', iat: now, exp: now + 60_000 };
  assert.equal(await verifyPasskeyUserVerificationToken(env, await signJwt({ ...base, userId: 'u2', method: 'passkey', purpose: 'backup.settings.repair' }, SECRET), 'u1', 'backup.settings.repair'), false);
  assert.equal(await verifyPasskeyUserVerificationToken(env, await signJwt({ ...base, userId: 'u1', method: 'passkey', purpose: 'backup.settings.repair' }, SECRET), 'u1', 'other.purpose' as UserVerificationPurpose), false);
  assert.equal(await verifyPasskeyUserVerificationToken(env, await signJwt({ ...base, userId: 'u1', method: 'magic', purpose: 'backup.settings.repair' }, SECRET), 'u1', 'backup.settings.repair'), false);
});

test('user verification token: expired rejected (millisecond expiry)', async () => {
  const now = Date.now();
  const token = await signJwt({
    typ: 'nodewarden.user-verification.v1',
    userId: 'u1',
    method: 'passkey',
    purpose: 'backup.settings.repair',
    iat: now - 120_000,
    exp: now - 1,
  }, SECRET);
  assert.equal(await verifyPasskeyUserVerificationToken(env, token, 'u1', 'backup.settings.repair'), false);
});

test('user verification token: tampered or wrong-secret rejected', async () => {
  const token = await createPasskeyUserVerificationToken(env, 'u1', 'backup.settings.repair');
  assert.equal(await verifyPasskeyUserVerificationToken(env, tamperPart(token, 1), 'u1', 'backup.settings.repair'), false);
  assert.equal(await verifyPasskeyUserVerificationToken(env, tamperPart(token, 2), 'u1', 'backup.settings.repair'), false);
  const otherEnv = { JWT_SECRET: OTHER_SECRET } as unknown as Env;
  assert.equal(await verifyPasskeyUserVerificationToken(otherEnv, token, 'u1', 'backup.settings.repair'), false);
});

// ---------------------------------------------------------------------------
// TOTP user-verification token (millisecond expiry, key + stamp binding)
// ---------------------------------------------------------------------------

test('totp user verification token: round-trip', async () => {
  const token = await createTotpUserVerificationToken(env, 'u1', 'totp-secret-1', 'stamp-1');
  assert.equal(await verifyTotpUserVerificationToken(env, token, 'u1', 'totp-secret-1', 'stamp-1'), true);

  // Token carries the historical 10-minute lifetime, iat/exp in milliseconds.
  const claims = await verifyJwt<{ typ: string; iat: number; exp: number; key?: string; stamp?: string }>(token, SECRET, () => true);
  assert.ok(claims);
  assert.equal(claims.typ, 'nodewarden.user-verification.v1');
  assert.equal(claims.exp - claims.iat, 10 * 60 * 1000);
  assert.equal(claims.key, 'totp-secret-1');
  assert.equal(claims.stamp, 'stamp-1');
});

test('totp user verification token: wrong key or stamp rejected', async () => {
  const token = await createTotpUserVerificationToken(env, 'u1', 'totp-secret-1', 'stamp-1');
  assert.equal(await verifyTotpUserVerificationToken(env, token, 'u1', 'totp-secret-2', 'stamp-1'), false);
  assert.equal(await verifyTotpUserVerificationToken(env, token, 'u1', 'totp-secret-1', 'stamp-2'), false);
  assert.equal(await verifyTotpUserVerificationToken(env, token, 'u2', 'totp-secret-1', 'stamp-1'), false);
});

test('totp user verification token: wrong purpose or method rejected', async () => {
  const now = Date.now();
  const base = { typ: 'nodewarden.user-verification.v1', userId: 'u1', key: 'k', stamp: 's', iat: now, exp: now + 60_000 };
  assert.equal(await verifyTotpUserVerificationToken(env, await signJwt({ ...base, method: 'totp', purpose: 'backup.settings.repair' }, SECRET), 'u1', 'k', 's'), false);
  assert.equal(await verifyTotpUserVerificationToken(env, await signJwt({ ...base, method: 'passkey', purpose: 'totp.setup' }, SECRET), 'u1', 'k', 's'), false);
  assert.equal(await verifyTotpUserVerificationToken(env, await signJwt({ ...base, method: 'magic', purpose: 'totp.setup' }, SECRET), 'u1', 'k', 's'), false);
});

test('totp user verification token: expired rejected (millisecond expiry)', async () => {
  const now = Date.now();
  const token = await signJwt({
    typ: 'nodewarden.user-verification.v1',
    userId: 'u1',
    method: 'totp',
    purpose: 'totp.setup',
    key: 'k',
    stamp: 's',
    iat: now - 120_000,
    exp: now - 1,
  }, SECRET);
  assert.equal(await verifyTotpUserVerificationToken(env, token, 'u1', 'k', 's'), false);
});

test('totp user verification token: tampered or wrong-secret rejected', async () => {
  const token = await createTotpUserVerificationToken(env, 'u1', 'k', 's');
  assert.equal(await verifyTotpUserVerificationToken(env, tamperPart(token, 1), 'u1', 'k', 's'), false);
  assert.equal(await verifyTotpUserVerificationToken(env, tamperPart(token, 2), 'u1', 'k', 's'), false);
  const otherEnv = { JWT_SECRET: OTHER_SECRET } as unknown as Env;
  assert.equal(await verifyTotpUserVerificationToken(otherEnv, token, 'u1', 'k', 's'), false);
});

test('totp user verification token: passkey token not accepted as totp token', async () => {
  const passkeyToken = await createPasskeyUserVerificationToken(env, 'u1', 'backup.settings.repair');
  assert.equal(await verifyTotpUserVerificationToken(env, passkeyToken, 'u1', 'k', 's'), false);
  const totpToken = await createTotpUserVerificationToken(env, 'u1', 'k', 's');
  assert.equal(await verifyPasskeyUserVerificationToken(env, totpToken, 'u1', 'backup.settings.repair'), false);
});

// ---------------------------------------------------------------------------
// Account passkey challenge token (millisecond expiry)
// ---------------------------------------------------------------------------

test('account passkey token: round-trip', async () => {
  const token = await createAccountPasskeyToken(env, { scope: 'CreateCredential', challenge: 'chal1', userId: 'u1', rpId: 'vault.example.test' });
  const payload = await verifyAccountPasskeyToken(env, token, 'CreateCredential');
  assert.ok(payload);
  assert.equal(payload.challenge, 'chal1');
  assert.equal(payload.userId, 'u1');
  assert.equal(payload.rpId, 'vault.example.test');
  assert.equal(payload.typ, 'nodewarden.account-passkey.challenge.v1');
  assert.equal(payload.exp - payload.iat, 7 * 60 * 1000);
});

test('account passkey token: ttlMs override honored', async () => {
  const token = await createAccountPasskeyToken(env, { scope: 'Authentication', challenge: 'chal2', rpId: 'r.example.test', ttlMs: 12_345 });
  const payload = await verifyAccountPasskeyToken(env, token, 'Authentication');
  assert.ok(payload);
  assert.equal(payload.exp - payload.iat, 12_345);
});

test('account passkey token: wrong typ rejected', async () => {
  const now = Date.now();
  const token = await signJwt({ typ: 'nodewarden.something-else', scope: 'Authentication', challenge: 'c', userId: null, rpId: 'r.example.test', iat: now, exp: now + 60_000 }, SECRET);
  assert.equal(await verifyAccountPasskeyToken(env, token, 'Authentication'), null);
});

test('account passkey token: wrong scope rejected', async () => {
  const token = await createAccountPasskeyToken(env, { scope: 'CreateCredential', challenge: 'chal1', userId: 'u1', rpId: 'vault.example.test' });
  assert.equal(await verifyAccountPasskeyToken(env, token, 'Authentication'), null);
});

test('account passkey token: missing challenge or rpId rejected', async () => {
  const now = Date.now();
  const base = { typ: 'nodewarden.account-passkey.challenge.v1', scope: 'Authentication', userId: null, iat: now, exp: now + 60_000 };
  assert.equal(await verifyAccountPasskeyToken(env, await signJwt({ ...base, challenge: '', rpId: 'r.example.test' }, SECRET), 'Authentication'), null);
  assert.equal(await verifyAccountPasskeyToken(env, await signJwt({ ...base, challenge: 'c', rpId: '' }, SECRET), 'Authentication'), null);
});

test('account passkey token: expired rejected (millisecond expiry)', async () => {
  const now = Date.now();
  const token = await signJwt({ typ: 'nodewarden.account-passkey.challenge.v1', scope: 'Authentication', challenge: 'c', userId: null, rpId: 'r.example.test', iat: now - 120_000, exp: now - 1 }, SECRET);
  assert.equal(await verifyAccountPasskeyToken(env, token, 'Authentication'), null);
});

test('account passkey token: tampered signature rejected', async () => {
  const token = await createAccountPasskeyToken(env, { scope: 'Authentication', challenge: 'c', rpId: 'r.example.test' });
  assert.equal(await verifyAccountPasskeyToken(env, tamperPart(token, 2), 'Authentication'), null);
});

// ---------------------------------------------------------------------------
// Cross-kind
// ---------------------------------------------------------------------------

test('a send access token is not accepted as an attachment upload token', async () => {
  const token = await createSendAccessToken('s1', SECRET);
  assert.equal(await verifyAttachmentUploadToken(token, SECRET), null);
});
