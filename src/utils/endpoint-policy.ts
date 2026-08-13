// SSRF boundary for outbound endpoint URLs (backup destinations, ...).
// Extracted verbatim from the backup settings module so the security fixes
// shipped there keep their exact behaviour: IPv6 loopback bypass, IPv4-mapped
// IPv6 loopback, URL-embedded credentials, scheme allowlist. The IP parsing
// primitives are also shared with the rate limiter, which builds identity
// keys from raw client IPs (it does not classify hosts as blocked/not).

function normalizeHostnameForPolicy(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

function parseIpv4Address(hostname: string): number[] | null {
  const parts = hostname.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) return -1;
    const value = Number(part);
    return Number.isInteger(value) && value >= 0 && value <= 255 ? value : -1;
  });
  return octets.every((value) => value >= 0) ? octets : null;
}

function isBlockedIpv4Address(octets: number[]): boolean {
  const [a, b, c] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

/**
 * Expand a hostname-form IPv6 literal to eight 4-digit hextets.
 * Needed so compressed forms like "::1" are not misclassified by a naive
 * "first non-empty hextet" check (which would read "1" and miss loopback).
 */
function expandIpv6Address(hostname: string): string[] | null {
  const normalized = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!normalized.includes(':')) return null;
  if (normalized.includes('.')) {
    // IPv4-embedded forms are handled separately by the caller.
    return null;
  }
  if ((normalized.match(/::/g) || []).length > 1) return null;

  const sides = normalized.split('::');
  const left = sides[0] ? sides[0].split(':').filter((part) => part.length > 0) : [];
  const right = sides.length > 1 && sides[1] ? sides[1].split(':').filter((part) => part.length > 0) : [];
  if (left.length + right.length > 8) return null;
  if (sides.length === 1 && left.length !== 8) return null;

  const missing = 8 - left.length - right.length;
  if (sides.length > 1 && missing < 0) return null;
  const middle = sides.length > 1 ? Array.from({ length: missing }, () => '0') : [];
  const parts = [...left, ...middle, ...right];
  if (parts.length !== 8) return null;

  const hextets: string[] = [];
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
    hextets.push(part.padStart(4, '0'));
  }
  return hextets;
}

function isBlockedIpv6Address(hostname: string): boolean {
  if (!hostname.includes(':')) return false;
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // IPv4-mapped dotted form: ::ffff:127.0.0.1
  const mappedIpv4 = normalized.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mappedIpv4) {
    const octets = parseIpv4Address(mappedIpv4[1]);
    return !octets || isBlockedIpv4Address(octets);
  }

  // IPv4-mapped hex form produced by some URL parsers: ::ffff:7f00:1
  const mappedHex = normalized.match(/::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (mappedHex) {
    const hi = Number.parseInt(mappedHex[1], 16);
    const lo = Number.parseInt(mappedHex[2], 16);
    if (!Number.isFinite(hi) || !Number.isFinite(lo)) return true;
    const octets = [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
    return isBlockedIpv4Address(octets);
  }

  const hextets = expandIpv6Address(normalized);
  if (!hextets) return true;
  const firstHextet = Number.parseInt(hextets[0], 16);
  if (!Number.isFinite(firstHextet)) return true;
  // After expansion, loopback (::1) and unspecified (::) have first hextet 0.
  return (
    firstHextet === 0 ||
    (firstHextet & 0xfe00) === 0xfc00 ||
    (firstHextet & 0xffc0) === 0xfe80 ||
    (firstHextet & 0xff00) === 0xff00 ||
    hextets.join(':').startsWith('2001:0db8:')
  );
}

function assertBackupEndpointHostAllowed(hostname: string, label: string): void {
  const normalized = normalizeHostnameForPolicy(hostname);
  if (!normalized) throw new Error(`${label} host is required`);
  if (
    normalized === 'localhost' ||
    normalized === 'localhost.localdomain' ||
    normalized.endsWith('.localhost.localdomain') ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.home.arpa') ||
    normalized.endsWith('.internal') ||
    normalized.endsWith('.lan') ||
    normalized === 'metadata.google.internal' ||
    normalized === 'localtest.me' ||
    normalized.endsWith('.localtest.me') ||
    normalized === 'lvh.me' ||
    normalized.endsWith('.lvh.me') ||
    normalized === 'vcap.me' ||
    normalized.endsWith('.vcap.me') ||
    normalized === 'nip.io' ||
    normalized.endsWith('.nip.io') ||
    normalized === 'sslip.io' ||
    normalized.endsWith('.sslip.io') ||
    normalized === 'xip.io' ||
    normalized.endsWith('.xip.io')
  ) {
    throw new Error(`${label} host is not allowed`);
  }
  const ipv4 = parseIpv4Address(normalized);
  if (ipv4 && isBlockedIpv4Address(ipv4)) {
    throw new Error(`${label} host is not allowed`);
  }
  if (isBlockedIpv6Address(normalized)) {
    throw new Error(`${label} host is not allowed`);
  }
}

/**
 * Reject any URL that is not a credential-free http(s) URL pointing at a
 * non-loopback / non-private / non-local host. Throws on violation.
 */
export function assertSafeEndpointUrl(value: string, label: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`${label} must start with http:// or https://`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} must not include credentials`);
  }
  if (parsed.search || parsed.hash) {
    throw new Error(`${label} must not include query or fragment`);
  }
  assertBackupEndpointHostAllowed(parsed.hostname, label);
}

export function normalizeBackupEndpointUrl(value: string, label: string): string {
  assertSafeEndpointUrl(value, label);
  return new URL(value).toString().replace(/\/+$/, '');
}

/**
 * Parse a raw client IP string into its canonical 8-hextet form.
 * Bracketed literals and zone identifiers are accepted; an IPv4-embedded
 * tail (::ffff:a.b.c.d) is rewritten to two hex hextets. Returns null when
 * the input is not a valid IPv4 or IPv6 address.
 */
function parseIpv6Address(input: string): number[] | null {
  let value = input.trim().toLowerCase();
  if (!value) return null;

  if (value.startsWith('[') && value.endsWith(']')) {
    value = value.slice(1, -1);
  }
  const zoneIndex = value.indexOf('%');
  if (zoneIndex >= 0) {
    value = value.slice(0, zoneIndex);
  }
  if (!value.includes(':')) return null;

  // Handle IPv4-mapped tail (e.g. ::ffff:192.0.2.1).
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) return null;
    const ipv4Tail = value.slice(lastColon + 1);
    const octets = parseIpv4Address(ipv4Tail);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = `${value.slice(0, lastColon)}:${high}:${low}`;
  }

  const doubleColon = value.indexOf('::');
  if (doubleColon !== value.lastIndexOf('::')) return null;

  const parsePart = (part: string): number | null => {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    const n = parseInt(part, 16);
    return Number.isNaN(n) ? null : n;
  };

  const parseParts = (parts: string[]): number[] | null => {
    const out: number[] = [];
    for (const p of parts) {
      if (!p) return null;
      const n = parsePart(p);
      if (n === null) return null;
      out.push(n);
    }
    return out;
  };

  if (doubleColon >= 0) {
    const [headRaw, tailRaw] = value.split('::');
    const head = headRaw ? headRaw.split(':') : [];
    const tail = tailRaw ? tailRaw.split(':') : [];

    const headNums = parseParts(head);
    const tailNums = parseParts(tail);
    if (!headNums || !tailNums) return null;

    const missing = 8 - (headNums.length + tailNums.length);
    if (missing < 1) return null;

    return [...headNums, ...new Array<number>(missing).fill(0), ...tailNums];
  }

  const all = parseParts(value.split(':'));
  if (!all || all.length !== 8) return null;
  return all;
}

export type IpAddressParseResult =
  | { kind: 'ipv4'; octets: number[] }
  | { kind: 'ipv6'; hextets: number[] };

/**
 * Shared IP-parsing core: classify a raw IP string as IPv4 or IPv6.
 * Used by the rate limiter to build identity keys. The endpoint URL policy
 * above classifies hosts with its own string-exact rules, so both keep their
 * existing behaviour.
 */
export function parseIpAddress(input: string): IpAddressParseResult | null {
  const ipv4 = parseIpv4Address(input);
  if (ipv4) return { kind: 'ipv4', octets: ipv4 };
  const ipv6 = parseIpv6Address(input);
  if (ipv6) return { kind: 'ipv6', hextets: ipv6 };
  return null;
}
