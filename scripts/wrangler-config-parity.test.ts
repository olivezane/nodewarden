import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

// wrangler.toml (R2 mode) and wrangler.kv.toml (KV mode) are maintained as
// near-duplicates. They must differ ONLY in the storage binding, otherwise
// one deployment mode silently misses config improvements (observability,
// migrations, compatibility date, assets, ...).

const STORAGE_SPECIFIC = /^(\[\[r2_buckets\]\]|\[\[kv_namespaces\]\]|bucket_name\s*=|binding\s*=\s*"(ATTACHMENTS|ATTACHMENTS_KV)")/;

function normalize(src: string): string[] {
  return src
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .filter((line) => !STORAGE_SPECIFIC.test(line))
    .sort();
}

test('wrangler.toml and wrangler.kv.toml differ only in storage binding', () => {
  const r2 = normalize(readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8'));
  const kv = normalize(readFileSync(new URL('../wrangler.kv.toml', import.meta.url), 'utf8'));

  assert.deepEqual(kv, r2);
});

test('shared config enables observability and D1 migrations', () => {
  for (const file of ['../wrangler.toml', '../wrangler.kv.toml']) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.ok(!/^\s*enabled\s*=\s*false/m.test(src), `${file}: no contradicting enabled=false`);
    assert.ok(/^\[observability\]\s*$/m.test(src), `${file}: [observability] missing`);
    assert.ok(/^\[observability\.logs\]\s*$/m.test(src), `${file}: [observability.logs] missing`);
    assert.ok(/^\[observability\.traces\]\s*$/m.test(src), `${file}: [observability.traces] missing`);
    assert.ok(/migrations_dir\s*=/m.test(src), `${file}: D1 migrations_dir missing`);
  }
});
