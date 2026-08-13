import { JWTPayload } from '../types';
import { LIMITS } from '../config/limits';

const hmacKeyCache = new Map<string, Promise<CryptoKey>>();

// Base64 URL encode
function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Base64 URL decode
function base64UrlDecode(str: string): Uint8Array {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function getHmacKey(secret: string): Promise<CryptoKey> {
  const cacheKey = secret;
  let cached = hmacKeyCache.get(cacheKey);
  if (cached) return cached;

  const encoder = new TextEncoder();
  cached = crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  hmacKeyCache.set(cacheKey, cached);
  return cached;
}

// Core: sign an arbitrary claims object as a three-part HMAC-SHA256 JWT.
// Callers set iat/exp themselves (units are per-kind: seconds or milliseconds).
export async function signJwt<T extends object>(payload: T, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encoder = new TextEncoder();

  const data = `${base64UrlEncode(encoder.encode(JSON.stringify(header)))}.${base64UrlEncode(encoder.encode(JSON.stringify(payload)))}`;

  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));

  return `${data}.${base64UrlEncode(new Uint8Array(signature))}`;
}

// Core: verify the signature (single constant-time comparison via crypto.subtle.verify),
// then run the per-kind claims validator (typ, claims, expiry).
export async function verifyJwt<T extends object>(
  token: string,
  secret: string,
  validate: (payload: T) => boolean
): Promise<T | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const data = `${headerB64}.${payloadB64}`;

    const key = await getHmacKey(secret);
    const valid = await crypto.subtle.verify('HMAC', key, base64UrlDecode(signatureB64), new TextEncoder().encode(data));
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as T;
    if (!validate(payload)) return null;

    return payload;
  } catch {
    return null;
  }
}

// Shared seconds-based expiry check. `undefined < now` is false, so a token
// missing `exp` is treated as not expired — leniency preserved as before.
function isExpiredSeconds(exp: unknown): boolean {
  return (exp as number) < Math.floor(Date.now() / 1000);
}

// Create JWT
export async function createJWT(payload: Omit<JWTPayload, 'iat' | 'exp' | 'iss' | 'premium' | 'email_verified' | 'amr'>, secret: string, expiresIn: number = LIMITS.auth.accessTokenTtlSeconds): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const fullPayload: JWTPayload = {
    ...payload,
    email_verified: true,  // required by mobile client
    amr: ['Application'],  // authentication methods reference - required by mobile client
    iat: now,
    exp: now + expiresIn,
    iss: 'nodewarden',
    premium: true,
  };

  return signJwt(fullPayload, secret);
}

// Verify JWT (access token: checks expiry only, as today)
export async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  return verifyJwt<JWTPayload>(token, secret, (payload) => !isExpiredSeconds(payload.exp));
}

// Create refresh token (simple random string)
export function createRefreshToken(): string {
  const bytes = new Uint8Array(LIMITS.auth.refreshTokenRandomBytes);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

// File download token payload
export interface FileDownloadClaims {
  cipherId: string;
  attachmentId: string;
  jti: string;
  exp: number;
}

export interface AttachmentUploadClaims {
  userId: string;
  cipherId: string;
  attachmentId: string;
  exp: number;
}

// Create file download token (short-lived, 5 minutes)
export async function createFileDownloadToken(
  cipherId: string,
  attachmentId: string,
  secret: string
): Promise<string> {
  const payload: FileDownloadClaims = {
    cipherId,
    attachmentId,
    jti: createRefreshToken(),
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.fileDownloadTokenTtlSeconds, // 5 minutes
  };

  return signJwt(payload, secret);
}

// Verify file download token (checks expiry only, as today)
export async function verifyFileDownloadToken(
  token: string,
  secret: string
): Promise<FileDownloadClaims | null> {
  return verifyJwt<FileDownloadClaims>(token, secret, (payload) => !isExpiredSeconds(payload.exp));
}

export async function createAttachmentUploadToken(
  userId: string,
  cipherId: string,
  attachmentId: string,
  secret: string
): Promise<string> {
  const payload: AttachmentUploadClaims = {
    userId,
    cipherId,
    attachmentId,
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  return signJwt(payload, secret);
}

export async function verifyAttachmentUploadToken(
  token: string,
  secret: string
): Promise<AttachmentUploadClaims | null> {
  return verifyJwt<AttachmentUploadClaims>(token, secret, (payload) => {
    if (isExpiredSeconds(payload.exp)) return false;
    if (!payload.userId || !payload.cipherId || !payload.attachmentId) return false;
    return true;
  });
}

export interface SendFileDownloadClaims {
  sendId: string;
  fileId: string;
  jti: string;
  exp: number;
}

export interface SendFileUploadClaims {
  userId: string;
  sendId: string;
  fileId: string;
  exp: number;
}

export async function createSendFileDownloadToken(
  sendId: string,
  fileId: string,
  secret: string
): Promise<string> {
  const payload: SendFileDownloadClaims = {
    sendId,
    fileId,
    jti: createRefreshToken(),
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  return signJwt(payload, secret);
}

export async function verifySendFileDownloadToken(
  token: string,
  secret: string
): Promise<SendFileDownloadClaims | null> {
  return verifyJwt<SendFileDownloadClaims>(token, secret, (payload) => {
    if (
      typeof payload.sendId !== 'string' ||
      typeof payload.fileId !== 'string' ||
      typeof payload.jti !== 'string' ||
      !payload.jti ||
      typeof payload.exp !== 'number'
    ) {
      return false;
    }
    if (isExpiredSeconds(payload.exp)) return false;
    return true;
  });
}

export async function createSendFileUploadToken(
  userId: string,
  sendId: string,
  fileId: string,
  secret: string
): Promise<string> {
  const payload: SendFileUploadClaims = {
    userId,
    sendId,
    fileId,
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  return signJwt(payload, secret);
}

export async function verifySendFileUploadToken(
  token: string,
  secret: string
): Promise<SendFileUploadClaims | null> {
  return verifyJwt<SendFileUploadClaims>(token, secret, (payload) => {
    if (isExpiredSeconds(payload.exp)) return false;
    if (!payload.userId || !payload.sendId || !payload.fileId) return false;
    return true;
  });
}

export interface SendAccessTokenClaims {
  sub: string; // send id
  typ: 'send_access';
  iat: number;
  exp: number;
}

export async function createSendAccessToken(sendId: string, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: SendAccessTokenClaims = {
    sub: sendId,
    typ: 'send_access',
    iat: now,
    exp: now + LIMITS.auth.sendAccessTokenTtlSeconds,
  };

  return signJwt(payload, secret);
}

export async function verifySendAccessToken(token: string, secret: string): Promise<SendAccessTokenClaims | null> {
  return verifyJwt<SendAccessTokenClaims>(token, secret, (payload) => {
    if (isExpiredSeconds(payload.exp)) return false;
    if (payload.typ !== 'send_access') return false;
    if (!payload.sub) return false;
    return true;
  });
}
