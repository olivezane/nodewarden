import type { Env } from '../types';
import { signJwt, verifyJwt } from './jwt';

const USER_VERIFICATION_TOKEN_TYPE = 'nodewarden.user-verification.v1';
const USER_VERIFICATION_TOKEN_TTL_MS = 5 * 60 * 1000;
const TOTP_USER_VERIFICATION_TOKEN_TTL_MS = 10 * 60 * 1000;

export type UserVerificationPurpose = 'backup.settings.repair' | 'totp.setup';

interface UserVerificationTokenPayload {
  typ: typeof USER_VERIFICATION_TOKEN_TYPE;
  userId: string;
  method: 'passkey' | 'totp';
  purpose: UserVerificationPurpose;
  key?: string;
  stamp?: string;
  iat: number;
  exp: number;
}

export async function createPasskeyUserVerificationToken(
  env: Env,
  userId: string,
  purpose: UserVerificationPurpose
): Promise<string> {
  const now = Date.now();
  const payload: UserVerificationTokenPayload = {
    typ: USER_VERIFICATION_TOKEN_TYPE,
    userId,
    method: 'passkey',
    purpose,
    iat: now,
    exp: now + USER_VERIFICATION_TOKEN_TTL_MS,
  };
  return signJwt(payload, env.JWT_SECRET);
}

export async function verifyPasskeyUserVerificationToken(
  env: Env,
  token: string,
  userId: string,
  purpose: UserVerificationPurpose
): Promise<boolean> {
  const verified = await verifyJwt<UserVerificationTokenPayload>(token, env.JWT_SECRET, (payload) => {
    if (!payload || payload.typ !== USER_VERIFICATION_TOKEN_TYPE) return false;
    if (payload.userId !== userId || payload.purpose !== purpose || payload.method !== 'passkey') return false;
    if (!Number.isFinite(payload.exp) || payload.exp < Date.now()) return false;
    return true;
  });
  return verified !== null;
}

// TOTP user-verification token. Binds the TOTP secret (key) and the user's
// security stamp so a token minted for one secret/stamp cannot be replayed
// against another. TTL stays at the historical 10 minutes.
export async function createTotpUserVerificationToken(
  env: Env,
  userId: string,
  key: string,
  stamp: string
): Promise<string> {
  const now = Date.now();
  const payload: UserVerificationTokenPayload = {
    typ: USER_VERIFICATION_TOKEN_TYPE,
    userId,
    method: 'totp',
    purpose: 'totp.setup',
    key,
    stamp,
    iat: now,
    exp: now + TOTP_USER_VERIFICATION_TOKEN_TTL_MS,
  };
  return signJwt(payload, env.JWT_SECRET);
}

export async function verifyTotpUserVerificationToken(
  env: Env,
  token: string,
  userId: string,
  key: string,
  stamp: string
): Promise<boolean> {
  const verified = await verifyJwt<UserVerificationTokenPayload>(token, env.JWT_SECRET, (payload) => {
    if (!payload || payload.typ !== USER_VERIFICATION_TOKEN_TYPE) return false;
    if (payload.userId !== userId || payload.purpose !== 'totp.setup' || payload.method !== 'totp') return false;
    if (payload.key !== key || payload.stamp !== stamp) return false;
    if (!Number.isFinite(payload.exp) || payload.exp < Date.now()) return false;
    return true;
  });
  return verified !== null;
}
