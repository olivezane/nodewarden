import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertSafeEndpointUrl,
  normalizeBackupEndpointUrl,
  parseIpAddress,
} from '../src/utils/endpoint-policy';
import { getClientIdentifier } from '../src/services/ratelimit';

const REJECTED_BY_HOST = /host is not allowed/;

function expectRejected(url: string, message: RegExp = REJECTED_BY_HOST): void {
  assert.throws(() => normalizeBackupEndpointUrl(url, 'endpoint'), message);
}

test('loopback and private IPv4 endpoints are rejected', () => {
  for (const url of [
    'https://127.0.0.1/',
    'https://127.0.0.2/',
    'https://0.0.0.0/',
    'https://10.0.0.1/',
    'https://172.16.0.1/',
    'https://192.168.1.1/',
    'https://169.254.169.254/', // cloud metadata endpoint
    'https://100.64.0.1/',      // carrier-grade NAT
  ]) {
    expectRejected(url);
  }
});

test('loopback IPv6 endpoints are rejected (IPv6 loopback bypass fix)', () => {
  for (const url of [
    'https://[::1]/',
    'https://[::]/',
    'https://[fe80::1]/',  // link-local
    'https://[fd00::1]/',  // unique local
    'https://[2001:db8::1]/', // documentation prefix
  ]) {
    expectRejected(url);
  }
});

test('IPv4-mapped IPv6 loopback endpoints are rejected', () => {
  for (const url of [
    'https://[::ffff:127.0.0.1]/', // dotted form
    'https://[::ffff:7f00:1]/',    // hex form produced by some URL parsers
    'https://[::ffff:10.0.0.1]/',
  ]) {
    expectRejected(url);
  }
});

test('URL-embedded credentials are rejected', () => {
  expectRejected('https://user:pass@example.com/', /must not include credentials/);
  expectRejected('https://user@example.com/', /must not include credentials/);
});

test('only http(s) schemes are accepted', () => {
  expectRejected('ftp://example.com/', /must start with http:\/\/ or https:\/\//);
  expectRejected('gopher://example.com/', /must start with http:\/\/ or https:\/\//);
  expectRejected('file:///etc/passwd', /must start with http:\/\/ or https:\/\//);
  expectRejected('not a url', /must be a valid URL/);
});

test('query strings and fragments are rejected', () => {
  expectRejected('https://example.com/?q=1', /must not include query or fragment/);
  expectRejected('https://example.com/#frag', /must not include query or fragment/);
});

test('normal http(s) endpoints are accepted and normalized', () => {
  assert.equal(normalizeBackupEndpointUrl('https://example.com/', 'endpoint'), 'https://example.com');
  assert.equal(normalizeBackupEndpointUrl('https://example.com', 'endpoint'), 'https://example.com');
  assert.equal(normalizeBackupEndpointUrl('http://s3.example.com:9000/', 'endpoint'), 'http://s3.example.com:9000');
  assert.equal(normalizeBackupEndpointUrl('https://[2606:4700::1111]/', 'endpoint'), 'https://[2606:4700::1111]');
});

test('assertSafeEndpointUrl applies the same policy', () => {
  assert.throws(() => assertSafeEndpointUrl('https://[::1]/', 'endpoint'), REJECTED_BY_HOST);
  assert.throws(() => assertSafeEndpointUrl('https://user@example.com/', 'endpoint'), /must not include credentials/);
  assert.throws(() => assertSafeEndpointUrl('ssh://example.com/', 'endpoint'), /must start with http:\/\/ or https:\/\//);
  assert.doesNotThrow(() => assertSafeEndpointUrl('https://example.com/', 'endpoint'));
});

test('shared IP parser classifies IPv4 and IPv6', () => {
  assert.deepEqual(parseIpAddress('192.168.1.1'), { kind: 'ipv4', octets: [192, 168, 1, 1] });
  assert.deepEqual(parseIpAddress('::1'), { kind: 'ipv6', hextets: [0, 0, 0, 0, 0, 0, 0, 1] });
  assert.deepEqual(parseIpAddress('::ffff:192.0.2.1'), {
    kind: 'ipv6',
    hextets: [0, 0, 0, 0, 0, 0xffff, 0xc000, 0x201],
  });
  assert.deepEqual(parseIpAddress('[fe80::1%25eth0]'), {
    kind: 'ipv6',
    hextets: [0xfe80, 0, 0, 0, 0, 0, 0, 1],
  });
  assert.equal(parseIpAddress('not-an-ip'), null);
  assert.equal(parseIpAddress('1.2.3'), null);
  assert.equal(parseIpAddress(''), null);
});

test('rate limiter client identity still classifies IPs identically', () => {
  const identify = (ip: string): string | null =>
    getClientIdentifier(new Request('https://example.test/', { headers: { 'CF-Connecting-IP': ip } }));

  assert.equal(identify('192.168.1.1'), 'ip4:192.168.1.1');
  assert.equal(identify('::ffff:192.0.2.1'), 'ip4:192.0.2.1');
  assert.equal(identify('::192.0.2.1'), 'ip4:192.0.2.1');
  assert.equal(identify('2001:4860:4860::8888'), 'ip6:2001:4860:4860:0000');
  assert.equal(identify('garbage'), null);
});
