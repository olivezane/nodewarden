// Test-only ESM loader for scripts/backup-runner.test.ts.
//
// Registers itself as a loader and redirects the runner module's imports of
// the backup service modules to namespaces that mix the real module with the
// mocked exports below. The test file controls the mocked behaviour through
// the exported `mockState` object, and must import this file before importing
// the runner.
//
// The generated mock namespace for a service module is:
//   export * from "<real module>";             // everything stays real
//   export { <mocked names> } from "<this file>";
import { register } from 'node:module';

// The loader file is evaluated once in the loader context and again as a
// regular module when the generated namespaces re-export from it. Only the
// first evaluation may register the hooks.
if (!globalThis.__nwBackupRunnerLoaderRegistered) {
  globalThis.__nwBackupRunnerLoaderRegistered = true;
  register(import.meta.url);
}

export const mockState = {
  makeSettings: () => ({ destinations: [] }),
  archive: null,
  runtimes: new Map(),
  currentSession: null,
  checksumFailuresRemaining: 0,
  // restore-path state
  importCalls: [],
  auditEvents: [],
  restoreProgressEvents: [],
  loadAttachmentResults: [],
  importResult: null,
  manifestAttachmentBlobs: [],
  dbAttachments: [],
};

export async function loadBackupSettings() {
  return structuredClone(mockState.makeSettings());
}

export async function updateBackupDestinationRuntime(_storage, destinationId, mutator) {
  const current = mockState.runtimes.get(destinationId) || {};
  const next = mutator(current);
  mockState.runtimes.set(destinationId, next);
  return next;
}

export async function buildBackupArchive(_env, _now, options) {
  if (options.progress) {
    await options.progress({ step: 'archive_users', fileName: mockState.archive.fileName });
    await options.progress({ step: 'archive_ready', fileName: mockState.archive.fileName });
  }
  return mockState.archive;
}

export async function verifyBackupArchiveFileNameChecksum() {
  if (mockState.checksumFailuresRemaining > 0) {
    mockState.checksumFailuresRemaining -= 1;
    return false;
  }
  return true;
}

export function createRemoteBackupTransferSession() {
  return mockState.currentSession;
}

export async function pruneRemoteBackupArchives() {
  return 0;
}

export async function writeAuditEvent(...args) {
  mockState.auditEvents.push(args);
}

export async function notifyUserBackupRestoreProgress(...args) {
  mockState.restoreProgressEvents.push(args[2]);
}

// `parseBackupArchive` is called synchronously by the runner, so this mock is
// sync. It returns a canned parse so the fixture bytes never need to be a
// real zip.
export function parseBackupArchive() {
  return {
    files: {},
    payload: {
      manifest: { attachmentBlobs: mockState.manifestAttachmentBlobs },
      db: { attachments: mockState.dbAttachments },
    },
  };
}

export async function importRemoteBackupArchiveBytes(
  bytes,
  _env,
  _actorUserId,
  replaceExisting,
  options,
  progress,
  restoreFileName
) {
  mockState.importCalls.push({ bytes, replaceExisting, restoreFileName });
  if (progress) {
    await progress({ step: 'restore_prepare', fileName: restoreFileName });
    await progress({ step: 'restore_restore_complete', fileName: restoreFileName, done: true, ok: true });
  }
  // Exercise the real loadAttachment seam: the batch download hits the DO
  // fetch, which is unreachable in tests, and must degrade to null.
  const blobName = mockState.manifestAttachmentBlobs[0]?.blobName;
  if (blobName && options?.loadAttachment) {
    mockState.loadAttachmentResults.push(await options.loadAttachment(blobName));
  }
  return mockState.importResult;
}

// Module file (as resolved) -> names to mock.
// `star: false` replaces the module entirely (the real one cannot be loaded
// under plain node, e.g. because it imports `cloudflare:workers`).
const MOCKED_FILES = {
  'src/services/backup-config.ts': {
    names: ['loadBackupSettings', 'updateBackupDestinationRuntime'],
  },
  'src/services/backup-archive.ts': {
    names: ['buildBackupArchive', 'verifyBackupArchiveFileNameChecksum', 'parseBackupArchive'],
  },
  'src/services/backup-import.ts': {
    names: ['importRemoteBackupArchiveBytes'],
  },
  'src/services/backup-uploader.ts': {
    names: ['createRemoteBackupTransferSession', 'pruneRemoteBackupArchives'],
  },
  'src/services/audit-events.ts': {
    names: ['writeAuditEvent'],
  },
  'durable/notifications-hub.ts': {
    star: false,
    names: ['notifyUserBackupRestoreProgress'],
  },
};

export async function resolve(specifier, context, nextResolve) {
  const resolved = await nextResolve(specifier, context);
  const file = Object.keys(MOCKED_FILES).find((key) => resolved.url.endsWith(key));
  const entry = file ? MOCKED_FILES[file] : null;
  // Mock only the runner's direct imports (parentURL gate). Nothing else in
  // the module graph is redirected — a test that also imported the handler
  // would load the real service modules for it, so keep test imports to the
  // runner alone.
  if (entry && context.parentURL?.endsWith('/src/services/backup-runner.ts')) {
    const source = [
      ...(entry.star === false ? [] : [`export * from ${JSON.stringify(resolved.url)};`]),
      `export { ${entry.names.join(', ')} } from ${JSON.stringify(import.meta.url)};`,
    ].join('\n');
    return {
      url: `data:text/javascript,${encodeURIComponent(source)}`,
      shortCircuit: true,
    };
  }
  return resolved;
}

export async function load(url, context, nextLoad) {
  if (url.startsWith('data:text/javascript,')) {
    return {
      format: 'module',
      source: decodeURIComponent(url.slice('data:text/javascript,'.length)),
      shortCircuit: true,
    };
  }
  return nextLoad(url, context);
}
