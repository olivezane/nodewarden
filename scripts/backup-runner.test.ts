import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env } from '../src/types';
import { StorageService } from '../src/services/storage';
import { mockState } from './backup-runner-loader.mjs';

// The loader (imported above) redirects the runner's imports of the backup
// service modules to mock implementations driven by `mockState` below. All
// mocked seams are pure in-memory: no HTTP surface, no D1, no crypto.

const archiveFixture = {
  fileName: 'backup-2026-08-02-000000.zip',
  bytes: new Uint8Array([1, 2, 3, 4]),
  manifest: { attachmentBlobs: [] },
};

function makeSettings() {
  return {
    destinations: [
      {
        id: 'dest-1',
        name: 'Test WebDAV',
        type: 'webdav',
        includeAttachments: false,
        schedule: {
          enabled: true,
          intervalHours: 24,
          startTime: '00:00',
          retentionCount: null,
          timezone: 'UTC',
        },
        destination: {
          baseUrl: 'https://webdav.example.test/dav',
          username: 'user',
          password: 'secret',
          remotePath: 'backups',
        },
      },
    ],
  };
}

let uploadCalls = 0;
let deleteCalls = 0;

function makeSession() {
  return {
    provider: 'webdav',
    uploadArchive: async () => {
      uploadCalls += 1;
      return { provider: 'webdav', remotePath: `backups/${archiveFixture.fileName}` };
    },
    stat: async () => null, // no metadata -> forces the read-back verification path
    download: async () => ({
      provider: 'webdav',
      remotePath: archiveFixture.fileName,
      fileName: archiveFixture.fileName,
      contentType: 'application/zip',
      bytes: archiveFixture.bytes,
    }),
    deleteFile: async () => {
      deleteCalls += 1;
    },
    putFile: async () => {},
    list: async () => ({ provider: 'webdav', currentPath: '', parentPath: null, items: [] }),
    exists: async () => true,
  };
}

mockState.makeSettings = makeSettings;
mockState.archive = archiveFixture;
mockState.runtimes = new Map();
mockState.currentSession = makeSession();
mockState.checksumFailuresRemaining = 0;

const { executeConfiguredBackup, importAndAuditRemoteBackupFile } = await import('../src/services/backup-runner');

const env = {} as Env;
const storage = {} as StorageService;

function recordProgress() {
  const events: Array<{ step: string; fileName: string; done?: boolean; ok?: boolean; error?: string | null }> = [];
  const progress = async (event: {
    operation: 'backup-remote-run';
    step: string;
    fileName: string;
    stageTitle: string;
    stageDetail: string;
    done?: boolean;
    ok?: boolean;
    error?: string | null;
  }) => {
    events.push({
      step: event.step,
      fileName: event.fileName,
      done: event.done,
      ok: event.ok,
      error: event.error ?? null,
    });
  };
  return { events, progress };
}

function resetCounters() {
  uploadCalls = 0;
  deleteCalls = 0;
}

test('transient verification failures retry and the backup eventually succeeds', async () => {
  resetCounters();
  mockState.checksumFailuresRemaining = 2;
  mockState.currentSession = makeSession();

  const { events, progress } = recordProgress();
  const result = await executeConfiguredBackup(env, storage, 'user-1', 'manual', undefined, null, progress, null);

  assert.equal(result.fileName, archiveFixture.fileName);
  assert.equal(result.provider, 'webdav');
  assert.equal(uploadCalls, 3, 'verification failures should re-upload for each retry');
  assert.equal(deleteCalls, 2, 'failed verifications should clean up the remote file');
  const last = events[events.length - 1];
  assert.equal(last.step, 'remote_run_complete');
  assert.equal(last.done, true);
  assert.equal(last.ok, true);
});

test('persistent verification failure aborts with the expected result', async () => {
  resetCounters();
  mockState.checksumFailuresRemaining = 100;
  mockState.currentSession = makeSession();

  const { events, progress } = recordProgress();
  await assert.rejects(
    executeConfiguredBackup(env, storage, 'user-1', 'manual', undefined, null, progress, null),
    (error: unknown) => error instanceof Error
      && error.message === 'Backup archive upload verification failed after 3 attempts: Remote backup ZIP checksum verification failed'
  );

  assert.equal(uploadCalls, 3);
  assert.equal(deleteCalls, 3);
  const last = events[events.length - 1];
  assert.equal(last.step, 'remote_run_failed');
  assert.equal(last.done, true);
  assert.equal(last.ok, false);
  assert.equal(last.error, 'Backup archive upload verification failed after 3 attempts: Remote backup ZIP checksum verification failed');
});

test('remote backup size verification failure surfaces in the abort error', async () => {
  resetCounters();
  mockState.checksumFailuresRemaining = 0;
  mockState.currentSession = {
    ...makeSession(),
    download: async () => ({
      provider: 'webdav',
      remotePath: archiveFixture.fileName,
      fileName: archiveFixture.fileName,
      contentType: 'application/zip',
      bytes: new Uint8Array(9), // length mismatch with the uploaded archive
    }),
  };

  const { progress } = recordProgress();
  await assert.rejects(
    executeConfiguredBackup(env, storage, 'user-1', 'manual', undefined, null, progress, null),
    /Backup archive upload verification failed after 3 attempts: Remote backup ZIP size verification failed/
  );
});

function makeImportResult() {
  return {
    auditActorUserId: 'user-1',
    result: {
      imported: { users: 1, ciphers: 2, attachments: 1 },
      skipped: { attachments: 0, reason: null },
    },
  };
}

function resetRestoreState() {
  mockState.importCalls = [];
  mockState.auditEvents = [];
  mockState.restoreProgressEvents = [];
  mockState.loadAttachmentResults = [];
  mockState.manifestAttachmentBlobs = [];
  mockState.dbAttachments = [];
}

const remoteFile = { fileName: archiveFixture.fileName, bytes: archiveFixture.bytes };
const destination = makeSettings().destinations[0];

test('remote restore propagates the import result, emits progress, and writes the audit log', async () => {
  resetRestoreState();
  mockState.importResult = makeImportResult();

  let keepAliveCalls = 0;
  const result = await importAndAuditRemoteBackupFile(
    env,
    storage,
    'user-1',
    remoteFile,
    destination,
    `backups/${archiveFixture.fileName}`,
    true,
    false,
    { note: 'manual restore' },
    null,
    async () => {
      keepAliveCalls += 1;
    }
  );

  assert.equal(result, mockState.importResult);
  assert.equal(mockState.importCalls.length, 1);
  assert.equal(mockState.importCalls[0].replaceExisting, true);
  assert.equal(mockState.importCalls[0].restoreFileName, archiveFixture.fileName);
  assert.ok(keepAliveCalls > 0, 'keepAlive must be touched during the restore');

  assert.deepEqual(
    mockState.restoreProgressEvents.map((payload) => payload.step),
    ['restore_prepare', 'restore_restore_complete']
  );
  assert.ok(
    mockState.restoreProgressEvents.every((payload) => payload.operation === 'backup-restore'),
    'restore progress events must carry the backup-restore operation'
  );

  const audit = mockState.auditEvents[0]?.[1];
  assert.equal(audit.action, 'admin.backup.import');
  assert.equal(audit.actorUserId, 'user-1');
  assert.equal(audit.metadata.trigger, 'remote');
  assert.equal(audit.metadata.remotePath, `backups/${archiveFixture.fileName}`);
  assert.equal(audit.metadata.destinationId, 'dest-1');
  assert.equal(audit.metadata.replaceExisting, true);
  assert.equal(audit.metadata.bytes, archiveFixture.bytes.byteLength);
});

test('remote restore resolves external attachments through the DO batch path, degrading to null when unreachable', async () => {
  resetRestoreState();
  mockState.manifestAttachmentBlobs = [{ cipherId: 'c1', attachmentId: 'a1', blobName: 'c1/a1' }];
  mockState.dbAttachments = [{ cipher_id: 'c1', id: 'a1' }];
  mockState.importResult = makeImportResult();

  await importAndAuditRemoteBackupFile(
    env,
    storage,
    'user-1',
    remoteFile,
    destination,
    `backups/${archiveFixture.fileName}`,
    false,
    true,
    null,
    null,
    null
  );

  assert.equal(mockState.loadAttachmentResults.length, 1);
  assert.equal(mockState.loadAttachmentResults[0], null, 'unreachable DO download must degrade to null so the restore proceeds');
});

test('progress events are emitted in the documented order', async () => {
  resetCounters();
  mockState.checksumFailuresRemaining = 0;
  // Metadata verification succeeds on the first attempt, so no retries occur.
  mockState.currentSession = {
    ...makeSession(),
    stat: async () => ({ size: archiveFixture.bytes.byteLength }),
  };

  const { events, progress } = recordProgress();
  const result = await executeConfiguredBackup(env, storage, null, 'scheduled', undefined, null, progress, null);

  assert.equal(uploadCalls, 1);
  assert.equal(result.fileName, archiveFixture.fileName);
  assert.deepEqual(
    events.map((event) => event.step),
    [
      'remote_run_prepare',
      'remote_run_archive_users',
      'remote_run_sync_attachments',
      'remote_run_upload_archive',
      'remote_run_verify_archive',
      'remote_run_cleanup',
      'remote_run_complete',
    ]
  );
  assert.ok(!events.some((event) => event.step === 'remote_run_archive_ready'), 'archive_ready build events must be suppressed');
  assert.equal(events[events.length - 1].ok, true);
  assert.equal(events[events.length - 1].done, true);
});
