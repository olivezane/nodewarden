import assert from 'node:assert/strict';
import test from 'node:test';

import {
  KV_MAX_OBJECT_BYTES,
  deleteBlobObject,
  getBlobObject,
  getBlobStorageMaxBytes,
  putBlobObject,
} from '../src/services/blob-store';

// KV is a fully supported attachment backend (wrangler.kv.toml). These tests
// pin its behavior: metadata round-trip, 25 MiB cap, streamed reads (no
// whole-object buffering), and delete.

class FakeKVNamespace {
  store = new Map<string, { value: ArrayBuffer; metadata?: Record<string, unknown> }>();
  lastGetType: string | null = null;

  async put(key: string, value: ArrayBuffer | ReadableStream, options?: { metadata?: unknown }): Promise<void> {
    const bytes = value instanceof ReadableStream ? new Uint8Array(await new Response(value).arrayBuffer()) : new Uint8Array(value);
    this.store.set(key, { value: bytes.buffer, metadata: options?.metadata as Record<string, unknown> });
  }

  async getWithMetadata(key: string, type?: string | { type?: string }): Promise<{
    value: ArrayBuffer | ReadableStream | null;
    metadata: Record<string, unknown> | null;
  }> {
    this.lastGetType = typeof type === 'string' ? type : type?.type ?? null;
    const entry = this.store.get(key);
    if (!entry) return { value: null, metadata: null };
    if (this.lastGetType === 'stream') {
      return { value: new Response(entry.value).body, metadata: entry.metadata ?? null };
    }
    return { value: entry.value, metadata: entry.metadata ?? null };
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

function kvEnv(): { ATTACHMENTS_KV: FakeKVNamespace } {
  return { ATTACHMENTS_KV: new FakeKVNamespace() };
}

test('KV put stores size/contentType metadata and get returns it', async () => {
  const env = kvEnv();
  const payload = new TextEncoder().encode('secret attachment').buffer;

  await putBlobObject(env, 'c1/a1', payload, { size: 17, contentType: 'application/octet-stream' });
  const object = await getBlobObject(env, 'c1/a1');

  assert.ok(object);
  assert.equal(object.size, 17);
  assert.equal(object.contentType, 'application/octet-stream');
});

test('KV get streams the value instead of buffering it', async () => {
  const env = kvEnv();
  const payload = new TextEncoder().encode('x'.repeat(1024)).buffer;
  await putBlobObject(env, 'c1/a1', payload, { size: 1024 });

  const object = await getBlobObject(env, 'c1/a1');
  assert.ok(object);
  assert.equal(env.ATTACHMENTS_KV.lastGetType, 'stream');
  assert.ok(object.body instanceof ReadableStream);

  const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
  assert.equal(bytes.byteLength, 1024);
});

test('KV put rejects objects larger than the 25 MiB KV limit', async () => {
  const env = kvEnv();
  await assert.rejects(
    putBlobObject(env, 'c1/big', new Uint8Array(1), { size: KV_MAX_OBJECT_BYTES + 1 }),
    /KV object too large/
  );
});

test('KV get returns null for missing keys', async () => {
  const env = kvEnv();
  assert.equal(await getBlobObject(env, 'missing/key'), null);
});

test('KV delete removes the object', async () => {
  const env = kvEnv();
  await putBlobObject(env, 'c1/a1', new TextEncoder().encode('data').buffer, { size: 4 });
  await deleteBlobObject(env, 'c1/a1');
  assert.equal(await getBlobObject(env, 'c1/a1'), null);
});

test('KV storage kind caps configured max bytes at 25 MiB', () => {
  assert.equal(getBlobStorageMaxBytes(kvEnv() as never, 100 * 1024 * 1024), KV_MAX_OBJECT_BYTES);
});
