import { LIMITS } from '../config/limits';
import { parseIpAddress } from '../utils/endpoint-policy';

// Rate limiting service.
// - Login attempts: D1-backed (low volume, security-critical, needs cross-colo persistence).
// - API budgets: Cloudflare Cache API (high volume, auto-expires, zero D1 writes).
// - Strict budgets: D1-backed fixed windows for low-volume anonymous sensitive endpoints.

const CONFIG = {
  LOGIN_MAX_ATTEMPTS: LIMITS.rateLimit.loginMaxAttempts,
  LOGIN_LOCKOUT_MINUTES: LIMITS.rateLimit.loginLockoutMinutes,
  API_WINDOW_SECONDS: LIMITS.rateLimit.apiWindowSeconds,
};

export class RateLimitService {
  private static loginIpTableReady = false;
  private static strictBudgetTableReady = false;
  private static lastLoginIpCleanupAt = 0;
  private static lastStrictBudgetCleanupAt = 0;

  private static readonly PERIODIC_CLEANUP_PROBABILITY = LIMITS.rateLimit.cleanupProbability;
  private static readonly LOGIN_IP_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.loginIpCleanupIntervalMs;
  private static readonly LOGIN_IP_RETENTION_MS = LIMITS.rateLimit.loginIpRetentionMs;
  private static readonly STRICT_BUDGET_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.loginIpCleanupIntervalMs;

  constructor(private db: D1Database) {}

  private shouldRunCleanup(lastRunAt: number, intervalMs: number): boolean {
    const now = Date.now();
    if (now - lastRunAt < intervalMs) return false;
    return Math.random() < RateLimitService.PERIODIC_CLEANUP_PROBABILITY;
  }

  private async maybeCleanupLoginAttemptsIp(nowMs: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastLoginIpCleanupAt, RateLimitService.LOGIN_IP_CLEANUP_INTERVAL_MS)) {
      return;
    }

    const cutoff = nowMs - RateLimitService.LOGIN_IP_RETENTION_MS;
    await this.db
      .prepare(
        'DELETE FROM login_attempts_ip WHERE updated_at < ? AND (locked_until IS NULL OR locked_until < ?)'
      )
      .bind(cutoff, nowMs)
      .run();
    RateLimitService.lastLoginIpCleanupAt = nowMs;
  }

  private async ensureLoginIpTable(): Promise<void> {
    if (RateLimitService.loginIpTableReady) return;

    await this.db
      .prepare(
        'CREATE TABLE IF NOT EXISTS login_attempts_ip (' +
        'ip TEXT PRIMARY KEY, ' +
        'attempts INTEGER NOT NULL, ' +
        'locked_until INTEGER, ' +
        'updated_at INTEGER NOT NULL' +
        ')'
      )
      .run();

    RateLimitService.loginIpTableReady = true;
  }

  private async ensureStrictBudgetTable(): Promise<void> {
    if (RateLimitService.strictBudgetTableReady) return;

    await this.db
      .prepare(
        'CREATE TABLE IF NOT EXISTS rate_limit_buckets (' +
        'bucket_key TEXT PRIMARY KEY, ' +
        'count INTEGER NOT NULL, ' +
        'expires_at INTEGER NOT NULL, ' +
        'updated_at INTEGER NOT NULL' +
        ')'
      )
      .run();

    await this.db
      .prepare('CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expires ON rate_limit_buckets(expires_at)')
      .run();
    RateLimitService.strictBudgetTableReady = true;
  }

  private async maybeCleanupStrictBudgets(nowMs: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastStrictBudgetCleanupAt, RateLimitService.STRICT_BUDGET_CLEANUP_INTERVAL_MS)) {
      return;
    }

    await this.db.prepare('DELETE FROM rate_limit_buckets WHERE expires_at < ?').bind(nowMs).run();
    RateLimitService.lastStrictBudgetCleanupAt = nowMs;
  }

  async checkLoginAttempt(ip: string): Promise<{
    allowed: boolean;
    remainingAttempts: number;
    retryAfterSeconds?: number;
  }> {
    await this.ensureLoginIpTable();

    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);

    const row = await this.db
      .prepare('SELECT attempts, locked_until FROM login_attempts_ip WHERE ip = ?')
      .bind(key)
      .first<{ attempts: number; locked_until: number | null }>();

    if (!row) {
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    if (row.locked_until && row.locked_until > now) {
      return {
        allowed: false,
        remainingAttempts: 0,
        retryAfterSeconds: Math.ceil((row.locked_until - now) / 1000),
      };
    }

    if (row.locked_until && row.locked_until <= now) {
      await this.db.prepare('DELETE FROM login_attempts_ip WHERE ip = ?').bind(key).run();
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    const remainingAttempts = Math.max(0, CONFIG.LOGIN_MAX_ATTEMPTS - (row.attempts || 0));
    return { allowed: true, remainingAttempts };
  }

  async recordFailedLogin(ip: string): Promise<{ locked: boolean; retryAfterSeconds?: number }> {
    await this.ensureLoginIpTable();

    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);

    // D1 in Workers forbids raw BEGIN/COMMIT statements.
    // Use a single atomic UPSERT to increment attempts.
    // This is concurrency-safe because the row is keyed by IP.
    await this.db
      .prepare(
        'INSERT INTO login_attempts_ip(ip, attempts, locked_until, updated_at) VALUES(?, 1, NULL, ?) ' +
        'ON CONFLICT(ip) DO UPDATE SET attempts = attempts + 1, updated_at = excluded.updated_at'
      )
      .bind(key, now)
      .run();

    const row = await this.db
      .prepare('SELECT attempts FROM login_attempts_ip WHERE ip = ?')
      .bind(key)
      .first<{ attempts: number }>();

    const attempts = row?.attempts || 1;
    if (attempts >= CONFIG.LOGIN_MAX_ATTEMPTS) {
      const lockedUntil = now + CONFIG.LOGIN_LOCKOUT_MINUTES * 60 * 1000;
      await this.db
        .prepare('UPDATE login_attempts_ip SET locked_until = ?, updated_at = ? WHERE ip = ?')
        .bind(lockedUntil, now, key)
        .run();
      return { locked: true, retryAfterSeconds: CONFIG.LOGIN_LOCKOUT_MINUTES * 60 };
    }

    return { locked: false };
  }

  async clearLoginAttempts(ip: string): Promise<void> {
    await this.ensureLoginIpTable();
    const key = ip.trim() || 'unknown';
    await this.db.prepare('DELETE FROM login_attempts_ip WHERE ip = ?').bind(key).run();
  }

  // Cache API-backed fixed-window rate limiter.
  // Uses Cloudflare edge cache instead of D1 — zero database writes, auto-expires via TTL.
  // Per-colo isolation is acceptable (matches Cloudflare's own rate limiting behaviour).
  private async consumeFixedWindowBudget(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    const nowSec = Math.floor(Date.now() / 1000);
    const windowStart = nowSec - (nowSec % windowSeconds);
    const windowEnd = windowStart + windowSeconds;
    const ttl = Math.max(1, windowEnd - nowSec);

    const cache = await caches.open('rate-limit');
    const cacheKey = new Request(`https://rl/${identifier}/${windowStart}`);

    const cached = await cache.match(cacheKey);
    let count = 0;
    if (cached) {
      count = parseInt(await cached.text(), 10) || 0;
    }

    if (count >= maxRequests) {
      return { allowed: false, remaining: 0, retryAfterSeconds: ttl };
    }

    count++;
    await cache.put(
      cacheKey,
      new Response(String(count), {
        headers: { 'Cache-Control': `public, max-age=${ttl}` },
      })
    );

    return { allowed: true, remaining: Math.max(0, maxRequests - count) };
  }

  async consumeStrictBudget(
    identifier: string,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeStrictBudgetWithWindow(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS);
  }

  async consumeStrictBudgetWithWindow(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    await this.ensureStrictBudgetTable();

    const key = String(identifier || '').trim() || 'unknown';
    const max = Math.max(1, Math.floor(maxRequests));
    const windowSize = Math.max(1, Math.floor(windowSeconds));
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const windowStart = nowSec - (nowSec % windowSize);
    const windowEndMs = (windowStart + windowSize) * 1000;
    const retryAfterSeconds = Math.max(1, Math.ceil((windowEndMs - nowMs) / 1000));
    const bucketKey = `${key}:${windowStart}`;

    await this.maybeCleanupStrictBudgets(nowMs);
    await this.db
      .prepare(
        'INSERT OR IGNORE INTO rate_limit_buckets(bucket_key, count, expires_at, updated_at) VALUES(?, 0, ?, ?)'
      )
      .bind(bucketKey, windowEndMs, nowMs)
      .run();

    const update = await this.db
      .prepare(
        'UPDATE rate_limit_buckets SET count = count + 1, expires_at = ?, updated_at = ? ' +
        'WHERE bucket_key = ? AND count < ?'
      )
      .bind(windowEndMs, nowMs, bucketKey, max)
      .run();

    const allowed = Number(update.meta?.changes ?? 0) > 0;
    const row = await this.db
      .prepare('SELECT count FROM rate_limit_buckets WHERE bucket_key = ?')
      .bind(bucketKey)
      .first<{ count: number }>();
    const count = Math.max(0, Number(row?.count || 0));

    if (!allowed) {
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }
    return { allowed: true, remaining: Math.max(0, max - count) };
  }

  // General-purpose fixed-window budget.
  // Callers supply an identifier (must be unique per rate-limit category) and the
  // per-window maximum.  This single method replaces all previous specialised
  // budget helpers (write / sync / knownDevice / publicSend).
  async consumeBudget(
    identifier: string,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS);
  }

  async consumeBudgetWithWindow(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(identifier, maxRequests, windowSeconds);
  }
}

function normalizeClientIpForRateLimit(rawIp: string): string | null {
  const input = rawIp.trim();
  if (!input) return null;

  const parsed = parseIpAddress(input);
  if (!parsed) return null;
  if (parsed.kind === 'ipv4') {
    return `ip4:${parsed.octets.join('.')}`;
  }

  // Handle IPv4-mapped / IPv4-compatible IPv6 as IPv4 identity.
  // Examples: ::ffff:192.0.2.1, ::192.0.2.1
  if (
    parsed.hextets[0] === 0 &&
    parsed.hextets[1] === 0 &&
    parsed.hextets[2] === 0 &&
    parsed.hextets[3] === 0 &&
    parsed.hextets[4] === 0 &&
    (parsed.hextets[5] === 0xffff || parsed.hextets[5] === 0)
  ) {
    const octets = [parsed.hextets[6] >> 8, parsed.hextets[6] & 0xff, parsed.hextets[7] >> 8, parsed.hextets[7] & 0xff];
    return `ip4:${octets.join('.')}`;
  }

  // Collapse to /64 to reduce brute-force bypass via IPv6 address rotation.
  const prefix64 = parsed.hextets
    .slice(0, 4)
    .map(part => part.toString(16).padStart(4, '0'))
    .join(':');
  return `ip6:${prefix64}`;
}

function isLocalRequest(request: Request): boolean {
  const isLoopbackHost = (host: string | null): boolean => {
    if (!host) return false;
    const normalized = host.split(':')[0].trim().toLowerCase();
    return (
      normalized === 'localhost' ||
      normalized.endsWith('.localhost') ||
      normalized === '127.0.0.1' ||
      normalized === '0.0.0.0' ||
      normalized === '::1' ||
      normalized === '[::1]'
    );
  };

  try {
    if (isLoopbackHost(new URL(request.url).hostname)) return true;
  } catch {
    // Ignore malformed URL and fall back to Host header check.
  }

  return isLoopbackHost(request.headers.get('Host'));
}

export function getClientIdentifier(request: Request): string | null {
  // Strict fallback order:
  // 1) CF-Connecting-IP
  // 2) X-Real-IP
  // 3) first item of X-Forwarded-For
  // If none are present/valid, treat client IP as unavailable.
  const candidates: Array<string | null> = [
    request.headers.get('CF-Connecting-IP'),
    request.headers.get('X-Real-IP'),
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || null,
  ];

  for (const raw of candidates) {
    if (!raw) continue;
    const normalized = normalizeClientIpForRateLimit(raw);
    if (normalized) return normalized;
  }

  // Local dev (wrangler dev / localhost): allow a deterministic loopback identifier.
  if (isLocalRequest(request)) {
    return 'ip4:127.0.0.1';
  }

  return null;
}
