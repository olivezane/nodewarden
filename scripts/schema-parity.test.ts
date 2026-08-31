import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

import { SCHEMA_STATEMENTS } from '../src/services/storage-schema';

// The runtime bootstrap (src/services/storage-schema.ts) and the
// wrangler-managed migration (migrations/0001_init.sql) must end up with the
// identical schema. They are maintained side by side; this test is the
// enforcement that used to be a comment in both files.

function buildRuntimeSchema(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  for (const statement of SCHEMA_STATEMENTS) {
    try {
      db.exec(statement);
    } catch (error) {
      const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
      // Same tolerance as executeSchemaStatement in storage-schema.ts.
      if (msg.includes('duplicate column name') || msg.includes('already exists')) continue;
      throw error;
    }
  }
  return db;
}

function buildMigrationSchema(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8'));
  return db;
}

function tableNames(db: DatabaseSync): string[] {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all() as Array<{ name: string }>;
  return rows.map((r) => r.name);
}

function columnsOf(db: DatabaseSync, table: string): string[] {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{
    name: string;
  }>;
  return rows.map((r) => r.name);
}

function indexesOf(db: DatabaseSync, table: string): Record<string, { unique: number; columns: string[] }> {
  const result: Record<string, { unique: number; columns: string[] }> = {};
  const list = db.prepare(`PRAGMA index_list(${table})`).all() as Array<{
    name: string;
    unique: number;
    origin: string;
  }>;
  for (const index of list) {
    if (index.origin === 'pk') continue;
    const cols = db.prepare(`PRAGMA index_info(${index.name})`).all() as Array<{ name: string }>;
    result[index.name] = { unique: index.unique, columns: cols.map((c) => c.name) };
  }
  return result;
}

function foreignKeysOf(db: DatabaseSync, table: string): string[] {
  const rows = db.prepare(`PRAGMA foreign_key_list(${table})`).all() as Array<{
    table: string;
    from: string;
    to: string;
  }>;
  return rows.map((r) => `${r.from}->${r.table}.${r.to}`).sort();
}

test('migrations/0001_init.sql produces the same schema as the runtime bootstrap', () => {
  const runtime = buildRuntimeSchema();
  const migration = buildMigrationSchema();

  const runtimeTables = tableNames(runtime);
  const migrationTables = tableNames(migration);
  assert.deepEqual(runtimeTables, migrationTables, 'table sets differ');

  for (const table of runtimeTables) {
    const context = `table ${table}`;
    assert.deepEqual(columnsOf(runtime, table), columnsOf(migration, table), `columns of ${context} differ`);
    assert.deepEqual(
      indexesOf(runtime, table),
      indexesOf(migration, table),
      `indexes of ${context} differ`
    );
    assert.deepEqual(
      foreignKeysOf(runtime, table),
      foreignKeysOf(migration, table),
      `foreign keys of ${context} differ`
    );
  }
});
