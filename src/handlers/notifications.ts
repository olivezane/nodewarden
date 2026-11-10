import { LIMITS } from '../config/limits';
import { AuthService } from '../services/auth';
import { RateLimitService } from '../services/ratelimit';
import { StorageService } from '../services/storage';
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import type { Env, JWTPayload } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import {
  createWebSocketConnectionToken,
  verifyWebSocketConnectionToken,
} from '../utils/websocket-connection-token';

const WEBSOCKET_CONNECTION_TOKEN_TTL_MS = 60 * 1000;

function extractAccessToken(request: Request): string | null {
  const authHeader = String(request.headers.get('Authorization') || '').trim();
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

async function authenticateAccessToken(request: Request, env: Env): Promise<JWTPayload | null> {
  const accessToken = extractAccessToken(request);
  if (!accessToken) return null;

  const auth = new AuthService(env);
  return auth.verifyAccessToken(`Bearer ${accessToken}`);
}

async function issueWebSocketConnectionToken(payload: JWTPayload, env: Env): Promise<string> {
  const expiresAt = Date.now() + WEBSOCKET_CONNECTION_TOKEN_TTL_MS;
  const token = await createWebSocketConnectionToken(payload.sub, expiresAt, env.JWT_SECRET);
  const id = env.NOTIFICATIONS_HUB.idFromName(payload.sub);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const response = await stub.fetch('https://notifications/internal/ws-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token,
      userId: payload.sub,
      deviceIdentifier: payload.did || null,
      expiresAt,
    }),
  });
  if (!response.ok) throw new Error('Failed to issue websocket connection token');
  return token;
}

async function consumeWebSocketConnectionToken(request: Request, env: Env): Promise<JWTPayload | null> {
  const token = String(new URL(request.url).searchParams.get('id') || '').trim();
  const claims = await verifyWebSocketConnectionToken(token, env.JWT_SECRET);
  if (!claims) return null;

  // Verify the signed routing claim before selecting a Durable Object. Otherwise an
  // attacker could activate arbitrary object names with forged token prefixes.
  const id = env.NOTIFICATIONS_HUB.idFromName(claims.userId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const response = await stub.fetch('https://notifications/internal/ws-token/consume', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  if (!response.ok) return null;

  const connection = (await response.json().catch(() => null)) as {
    userId?: string;
    deviceIdentifier?: string | null;
  } | null;
  if (connection?.userId !== claims.userId) return null;

  return {
    sub: claims.userId,
    did: String(connection.deviceIdentifier || '').trim() || undefined,
  } as JWTPayload;
}

async function authenticateNotificationsHub(request: Request, env: Env): Promise<JWTPayload | null> {
  // Never accept an access JWT from the URL: URLs are routinely retained by logs,
  // browser history, proxies, monitoring, and error tracking systems.
  if (request.headers.has('Authorization')) {
    return authenticateAccessToken(request, env);
  }
  return consumeWebSocketConnectionToken(request, env);
}

async function consumeNotificationsBudget(env: Env, userId: string): Promise<Response | null> {
  const rateLimit = new RateLimitService(env.DB);
  const check = await rateLimit.consumeBudget(
    `${userId}:notifications`,
    LIMITS.rateLimit.notificationsRequestsPerMinute
  );
  if (check.allowed) return null;
  return new Response(
    JSON.stringify({
      error: 'Too many requests',
      error_description: `Rate limit exceeded. Try again in ${check.retryAfterSeconds} seconds.`,
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(check.retryAfterSeconds || 60),
      },
    }
  );
}

export async function handleNotificationsNegotiate(request: Request, env: Env): Promise<Response> {
  const payload = await authenticateAccessToken(request, env);
  if (!payload?.sub) return errorResponse('Unauthorized', 401);

  const limited = await consumeNotificationsBudget(env, payload.sub);
  if (limited) return limited;

  const connectionToken = await issueWebSocketConnectionToken(payload, env);
  return jsonResponse(
    {
      connectionId: generateUUID(),
      connectionToken,
      negotiateVersion: 1,
      availableTransports: [
        {
          transport: 'WebSockets',
          transferFormats: ['Text', 'Binary'],
        },
      ],
    },
    200,
    { 'Cache-Control': 'no-store' }
  );
}

export async function handleNotificationsHub(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }
  const payload = await authenticateNotificationsHub(request, env);
  if (!payload?.sub) return errorResponse('Unauthorized', 401);

  const limited = await consumeNotificationsBudget(env, payload.sub);
  if (limited) return limited;

  const userId = payload.sub;
  const id = env.NOTIFICATIONS_HUB.idFromName(userId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.set('nw_uid', userId);
  if (payload.did) {
    forwardedUrl.searchParams.set('nw_did', payload.did);
  }
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}

export async function handleAnonymousNotificationsHub(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const authRequestId = String(url.searchParams.get('Token') || url.searchParams.get('token') || '').trim();
  if (!authRequestId) return errorResponse('Token is required', 400);
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }

  const storage = new StorageService(env.DB);
  const authRequest = await storage.getAuthRequestById(authRequestId);
  if (!authRequest || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }

  const id = env.NOTIFICATIONS_HUB.idFromName(authRequestId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.set('nw_auth_request_id', authRequestId);
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}
