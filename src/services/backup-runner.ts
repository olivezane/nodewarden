import type { Env } from '../types';
import {
  type BackupArchiveBundle,
  buildBackupArchive,
  parseBackupArchive,
  verifyBackupArchiveFileNameChecksum,
  isSafeBackupAttachmentBlobName,
} from './backup-archive';
import {
  type BackupDestinationRecord,
  type BackupSettings,
  type WebDavBackupDestination,
  getBackupLocalDateKey,
  loadBackupSettings,
  requireBackupDestination,
  updateBackupDestinationRuntime,
} from './backup-config';
import {
  type BackupImportExecutionResult,
  type BackupRestoreProgressReporter,
  importRemoteBackupArchiveBytes,
} from './backup-import';
import {
  type RemoteBackupFile,
  type RemoteBackupTransferSession,
  createRemoteBackupTransferSession,
  pruneRemoteBackupArchives,
  uploadBackupArchive,
} from './backup-uploader';
import { StorageService } from './storage';
import { auditRequestMetadata, writeAuditEvent } from './audit-events';
import { getBlobObject } from './blob-store';
import { notifyUserBackupRestoreProgress } from '../durable/notifications-hub';
import { unzipSync } from 'fflate';

export async function writeAuditLog(
  storage: StorageService,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null,
  request?: Request
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId,
    action,
    targetType,
    targetId,
    category: 'data',
    level: action.endsWith('.failed') ? 'error' : 'info',
    metadata: {
      ...(metadata || {}),
      ...(request ? auditRequestMetadata(request) : {}),
    },
  });
}

export function getBackupDestinationSummary(destination: BackupDestinationRecord | null): Record<string, unknown> {
  if (!destination) {
    return {
      destinationId: null,
      destinationName: null,
      destinationType: null,
    };
  }
  return {
    destinationId: destination.id,
    destinationName: destination.name,
    destinationType: destination.type,
  };
}

const REMOTE_ATTACHMENT_INDEX_PATH = 'attachments/.nodewarden-attachment-index.v1.json';

interface RemoteAttachmentIndexPayload {
  version: 1;
  blobs: Record<string, { sizeBytes: number; updatedAt: string }>;
}

const REMOTE_ATTACHMENT_SYNC_EXTERNAL_SUBREQUEST_LIMIT = 50;
const REMOTE_ATTACHMENT_SYNC_SUBREQUEST_RESERVE = 6;
const REMOTE_ATTACHMENT_SYNC_MAX_WEB_DAV_BATCH_SIZE = 18;
const REMOTE_ATTACHMENT_SYNC_MAX_S3_BATCH_SIZE = 40;
const REMOTE_ATTACHMENT_RESTORE_BATCH_SIZE = 40;

function countRemotePathSegments(value: string): number {
  return String(value || '').replace(/\\/g, '/').split('/').filter(Boolean).length;
}

function getRemoteAttachmentSyncBatchSize(destination: BackupDestinationRecord): number {
  if (destination.type === 's3') {
    return REMOTE_ATTACHMENT_SYNC_MAX_S3_BATCH_SIZE;
  }

  const remotePath = String((destination.destination as WebDavBackupDestination).remotePath || '');
  const fixedWebDavDirectoryCalls = countRemotePathSegments(remotePath) + 1; // remotePath plus the shared "attachments" dir.
  const available = REMOTE_ATTACHMENT_SYNC_EXTERNAL_SUBREQUEST_LIMIT
    - REMOTE_ATTACHMENT_SYNC_SUBREQUEST_RESERVE
    - fixedWebDavDirectoryCalls;

  if (available < 2) {
    throw new Error('WebDAV remote backup path is too deep for safe attachment batching');
  }

  return Math.max(1, Math.min(
    REMOTE_ATTACHMENT_SYNC_MAX_WEB_DAV_BATCH_SIZE,
    Math.floor(available / 2)
  ));
}

async function loadRemoteAttachmentIndex(session: RemoteBackupTransferSession): Promise<Map<string, number>> {
  try {
    const file = await session.download(REMOTE_ATTACHMENT_INDEX_PATH);
    const payload = JSON.parse(new TextDecoder().decode(file.bytes)) as RemoteAttachmentIndexPayload;
    if (payload?.version !== 1 || !payload.blobs || typeof payload.blobs !== 'object') {
      return new Map<string, number>();
    }
    return new Map(
      Object.entries(payload.blobs)
        .filter(([key, value]) => !!String(key || '').trim() && Number.isFinite(Number(value?.sizeBytes || 0)))
        .map(([key, value]) => [key, Number(value.sizeBytes || 0)])
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.toLowerCase();
    // Some WebDAV providers return non-standard codes such as 530 when the
    // attachment index does not exist yet. Treat these "missing file" style
    // responses as an empty index so first-time incremental backups can proceed.
    if (
      normalized.includes('404')
      || normalized.includes('403')
      || normalized.includes('530')
      || normalized.includes('not found')
      || normalized.includes('file not found')
      || normalized.includes('does not exist')
      || normalized.includes('please select a backup file')
    ) {
      return new Map<string, number>();
    }
    throw error;
  }
}

async function saveRemoteAttachmentIndex(
  session: RemoteBackupTransferSession,
  index: Map<string, number>
): Promise<void> {
  const payload: RemoteAttachmentIndexPayload = {
    version: 1,
    blobs: Object.fromEntries(
      Array.from(index.entries()).map(([blobName, sizeBytes]) => [
        blobName,
        {
          sizeBytes,
          updatedAt: new Date().toISOString(),
        },
      ])
    ),
  };
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  await session.putFile(REMOTE_ATTACHMENT_INDEX_PATH, bytes, {
    contentType: 'application/json; charset=utf-8',
  });
}

async function uploadRemoteAttachmentChunk(
  env: Env,
  destination: BackupDestinationRecord,
  attachments: Array<{ blobName: string }>
): Promise<void> {
  if (!attachments.length) return;
  const id = env.BACKUP_TRANSFER_RUNNER.idFromName('remote-attachment-sync');
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch('https://backup-transfer/internal/upload-attachment-chunk', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      destination,
      attachments,
    }),
  });
  if (!response.ok) {
    let message = `Attachment sync failed: ${response.status}`;
    try {
      const payload = await response.json<{ error?: string }>();
      if (payload?.error) {
        message = payload.error;
      }
    } catch {
      // Ignore JSON parse failures and preserve the status-based error.
    }
    throw new Error(message);
  }
}

async function verifyUploadedBackupArchive(
  session: RemoteBackupTransferSession,
  archive: BackupArchiveBundle
): Promise<'metadata' | 'download'> {
  try {
    const stat = await session.stat(archive.fileName);
    if (stat?.size === archive.bytes.byteLength) {
      return 'metadata';
    }
  } catch {
    // Fall through to a full read-back verification when lightweight metadata is unavailable.
  }

  const remoteFile = await session.download(archive.fileName);
  const checksumOk = await verifyBackupArchiveFileNameChecksum(remoteFile.bytes, archive.fileName);
  if (!checksumOk) {
    throw new Error('Remote backup ZIP checksum verification failed');
  }
  if (remoteFile.bytes.byteLength !== archive.bytes.byteLength) {
    throw new Error('Remote backup ZIP size verification failed');
  }
  return 'download';
}

export async function executeConfiguredBackup(
  env: Env,
  storage: StorageService,
  actorUserId: string | null,
  trigger: 'manual' | 'scheduled',
  destinationId?: string | null,
  keepAlive?: (() => Promise<void>) | null,
  progress?: ((event: {
    operation: 'backup-remote-run';
    step: string;
    fileName: string;
    stageTitle: string;
    stageDetail: string;
    done?: boolean;
    ok?: boolean;
    error?: string | null;
  }) => Promise<void>) | null,
  auditMetadata?: Record<string, unknown> | null
): Promise<{ fileName: string; fileSize: number; remotePath: string; provider: string }> {
  const maxArchiveUploadAttempts = 3;
  const touchLease = async () => {
    await keepAlive?.();
  };
  const currentSettings = await loadBackupSettings(storage, env, 'UTC');
  const destination = requireBackupDestination(currentSettings, destinationId);

  const now = new Date();
  await touchLease();
  destination.runtime = await updateBackupDestinationRuntime(storage, destination.id, (runtime) => ({
    ...runtime,
    lastAttemptAt: now.toISOString(),
    lastAttemptLocalDate: getBackupLocalDateKey(now, destination.schedule.timezone),
    lastErrorAt: null,
    lastErrorMessage: null,
  }));

  try {
    await touchLease();
    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_prepare',
      fileName: '',
      stageTitle: 'txt_backup_remote_run_progress_prepare_title',
      stageDetail: 'txt_backup_remote_run_progress_prepare_detail',
    });
    await touchLease();
    const archive = await buildBackupArchive(env, now, {
      includeAttachments: destination.includeAttachments,
      timeZone: destination.schedule.timezone,
      progress: progress
        ? async (event) => {
          if (event.step === 'archive_ready') {
            return;
          }
          await progress({
            operation: 'backup-remote-run',
            step: `remote_run_${event.step}`,
            fileName: event.fileName || '',
            stageTitle: event.stageTitle,
            stageDetail: event.stageDetail,
          });
        }
        : undefined,
    });
    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_sync_attachments',
      fileName: archive.fileName,
      stageTitle: 'txt_backup_remote_run_progress_sync_attachments_title',
      stageDetail: destination.includeAttachments
        ? 'txt_backup_remote_run_progress_sync_attachments_detail'
        : 'txt_backup_remote_run_progress_sync_attachments_skipped_detail',
    });
    const remoteSession = createRemoteBackupTransferSession(destination);
    if (destination.includeAttachments) {
      await touchLease();
      const remoteAttachmentIndex = await loadRemoteAttachmentIndex(remoteSession);
      const pendingAttachments = (archive.manifest.attachmentBlobs || [])
        .filter((attachment) => remoteAttachmentIndex.get(attachment.blobName) !== attachment.sizeBytes);
      const attachmentSyncBatchSize = getRemoteAttachmentSyncBatchSize(destination);
      for (let i = 0; i < pendingAttachments.length; i += attachmentSyncBatchSize) {
        await touchLease();
        const chunk = pendingAttachments
          .slice(i, i + attachmentSyncBatchSize)
          .map((attachment) => ({ blobName: attachment.blobName }));
        await uploadRemoteAttachmentChunk(env, destination, chunk);
      }
      if (pendingAttachments.length) {
        for (const attachment of pendingAttachments) {
          remoteAttachmentIndex.set(attachment.blobName, attachment.sizeBytes);
        }
        await touchLease();
        await saveRemoteAttachmentIndex(remoteSession, remoteAttachmentIndex);
      }
    }
    let upload: Awaited<ReturnType<typeof uploadBackupArchive>> | null = null;
    let uploadVerificationMethod: 'metadata' | 'download' | null = null;
    for (let attempt = 1; attempt <= maxArchiveUploadAttempts; attempt++) {
      await touchLease();
      await progress?.({
        operation: 'backup-remote-run',
        step: 'remote_run_upload_archive',
        fileName: archive.fileName,
        stageTitle: 'txt_backup_remote_run_progress_upload_title',
        stageDetail: 'txt_backup_remote_run_progress_upload_detail',
      });
      upload = await remoteSession.uploadArchive(archive.bytes, archive.fileName);
      try {
        await touchLease();
        await progress?.({
          operation: 'backup-remote-run',
          step: 'remote_run_verify_archive',
          fileName: archive.fileName,
          stageTitle: 'txt_backup_remote_run_progress_verify_title',
          stageDetail: 'txt_backup_remote_run_progress_verify_detail',
        });
        uploadVerificationMethod = await verifyUploadedBackupArchive(remoteSession, archive);
        break;
      } catch (error) {
        await remoteSession.deleteFile(archive.fileName).catch(() => undefined);
        if (attempt === maxArchiveUploadAttempts) {
          const message = error instanceof Error ? error.message : 'Remote backup ZIP verification failed';
          throw new Error(`Backup archive upload verification failed after ${maxArchiveUploadAttempts} attempts: ${message}`);
        }
      }
    }
    if (!upload) {
      throw new Error('Backup archive upload failed');
    }
    let prunedFileCount = 0;
    let pruneErrorMessage: string | null = null;
    try {
      await touchLease();
      await progress?.({
        operation: 'backup-remote-run',
        step: 'remote_run_cleanup',
        fileName: archive.fileName,
        stageTitle: 'txt_backup_remote_run_progress_cleanup_title',
        stageDetail: 'txt_backup_remote_run_progress_cleanup_detail',
      });
      prunedFileCount = await pruneRemoteBackupArchives(destination, destination.schedule.retentionCount, archive.fileName);
    } catch (error) {
      pruneErrorMessage = error instanceof Error ? error.message : 'Old backup cleanup failed';
    }

    await touchLease();
    destination.runtime = await updateBackupDestinationRuntime(storage, destination.id, (runtime) => ({
      ...runtime,
      lastSuccessAt: new Date().toISOString(),
      lastErrorAt: null,
      lastErrorMessage: null,
      lastUploadedFileName: archive.fileName,
      lastUploadedSizeBytes: archive.bytes.byteLength,
      lastUploadedDestination: upload.remotePath,
    }));

    await touchLease();
    await writeAuditLog(storage, actorUserId, `admin.backup.remote.${trigger}`, 'backup', null, {
      ...getBackupDestinationSummary(destination),
      provider: upload.provider,
      remotePath: upload.remotePath,
      fileName: archive.fileName,
      fileBytes: archive.bytes.byteLength,
      uploadVerificationAttempts: maxArchiveUploadAttempts,
      uploadVerificationMethod,
      prunedFileCount,
      pruneError: pruneErrorMessage,
      ...(auditMetadata || {}),
    });

    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_complete',
      fileName: archive.fileName,
      stageTitle: 'txt_backup_remote_run_progress_complete_title',
      stageDetail: 'txt_backup_remote_run_progress_complete_detail',
      done: true,
      ok: true,
    });

    return {
      fileName: archive.fileName,
      fileSize: archive.bytes.byteLength,
      remotePath: upload.remotePath,
      provider: upload.provider,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Backup upload failed';
    await touchLease();
    destination.runtime = await updateBackupDestinationRuntime(storage, destination.id, (runtime) => ({
      ...runtime,
      lastErrorAt: new Date().toISOString(),
      lastErrorMessage: errorMessage,
    }));

    await touchLease();
    await writeAuditLog(storage, actorUserId, `admin.backup.remote.${trigger}.failed`, 'backup', null, {
      ...getBackupDestinationSummary(destination),
      error: errorMessage,
      ...(auditMetadata || {}),
    });
    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_failed',
      fileName: '',
      stageTitle: 'txt_backup_remote_run_progress_failed_title',
      stageDetail: 'txt_backup_remote_run_progress_failed_detail',
      done: true,
      ok: false,
      error: errorMessage,
    });
    throw error;
  }
}

interface DurableBackupRunResponse {
  result: {
    fileName: string;
    fileSize: number;
    remotePath: string;
    provider: string;
  };
  settings: BackupSettings;
}

interface InternalBackupTransferRequestOptions {
  name: string;
  path: string;
  body?: unknown;
  errorPrefix: string;
  conflictStatus?: number;
  extractErrorJson?: boolean;
}

async function requestBackupTransferInternal(
  env: Env,
  options: InternalBackupTransferRequestOptions
): Promise<Response | null> {
  const id = env.BACKUP_TRANSFER_RUNNER.idFromName(options.name);
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch(`https://backup-transfer${options.path}`, {
    method: 'POST',
    headers: options.body === undefined ? undefined : {
      'Content-Type': 'application/json; charset=utf-8',
    },
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  if (options.conflictStatus !== undefined && response.status === options.conflictStatus) {
    return null;
  }
  if (!response.ok) {
    let message = `${options.errorPrefix}: ${response.status}`;
    if (options.extractErrorJson !== false) {
      try {
        const body = await response.json<{ error?: string }>();
        if (body?.error) message = body.error;
      } catch {
        // Preserve the status-based message when the DO returns a non-JSON error.
      }
    }
    throw new Error(message);
  }
  return response;
}

export async function runConfiguredBackupInDurableObject(
  env: Env,
  payload: {
    actorUserId: string | null;
    auditMetadata?: Record<string, unknown> | null;
    destinationId?: string | null;
    targetDeviceIdentifier?: string | null;
    trigger: 'manual' | 'scheduled';
  }
): Promise<DurableBackupRunResponse | null> {
  const response = await requestBackupTransferInternal(env, {
    name: 'configured-backup-runner',
    path: '/internal/run-configured-backup',
    body: payload,
    errorPrefix: 'Backup run failed',
    conflictStatus: 409,
  });
  if (!response) {
    return null;
  }
  const body = await response.json<DurableBackupRunResponse>();
  if (!body?.result || !body?.settings) {
    throw new Error('Backup run response is invalid');
  }
  return body;
}

export async function runScheduledBackupsInDurableObject(env: Env): Promise<void> {
  await requestBackupTransferInternal(env, {
    name: 'configured-backup-runner',
    path: '/internal/run-scheduled-backups',
    errorPrefix: 'Scheduled backup failed',
    conflictStatus: 409,
  });
}

async function downloadRemoteAttachmentViaDurableObject(
  env: Env,
  destination: BackupDestinationRecord,
  blobName: string
): Promise<Uint8Array | null> {
  const response = await requestBackupTransferInternal(env, {
    name: 'remote-attachment-restore',
    path: '/internal/download-remote-attachment',
    body: {
      destination,
      blobName,
    },
    errorPrefix: 'Remote attachment download failed',
    conflictStatus: 404,
    extractErrorJson: false,
  });
  if (!response) {
    return null;
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function downloadRemoteAttachmentBatchViaDurableObject(
  env: Env,
  destination: BackupDestinationRecord,
  blobNames: string[]
): Promise<Map<string, Uint8Array>> {
  const names = Array.from(new Set(blobNames.map((blobName) => String(blobName || '').trim()).filter(Boolean)));
  const result = new Map<string, Uint8Array>();
  if (!names.length) return result;

  const response = await requestBackupTransferInternal(env, {
    name: 'remote-attachment-restore',
    path: '/internal/download-remote-attachment-batch',
    body: {
      destination,
      blobNames: names,
    },
    errorPrefix: 'Remote attachment batch download failed',
    extractErrorJson: false,
  });
  if (!response) return result;

  const files = unzipSync(new Uint8Array(await response.arrayBuffer()));
  const manifestBytes = files['manifest.json'];
  if (!manifestBytes) return result;
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as {
    entries?: Array<{ blobName?: string; path?: string }>;
  };
  for (const entry of manifest.entries || []) {
    const blobName = String(entry.blobName || '').trim();
    const path = String(entry.path || '').trim();
    const bytes = path ? files[path] : null;
    if (blobName && bytes) {
      result.set(blobName, bytes);
    }
  }
  return result;
}

function collectExternalRemoteAttachmentBlobNames(archiveBytes: Uint8Array): string[] {
  const parsed = parseBackupArchive(archiveBytes, { allowExternalAttachmentBlobs: true });
  const refs = new Map(
    (parsed.payload.manifest.attachmentBlobs || [])
      .map((item) => [`${String(item.cipherId || '').trim()}/${String(item.attachmentId || '').trim()}`, item])
  );
  const names: string[] = [];
  const seen = new Set<string>();

  for (const row of parsed.payload.db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;
    if (parsed.files[inlinePath]) continue;
    const ref = refs.get(`${cipherId}/${attachmentId}`);
    const blobName = String(ref?.blobName || '').trim();
    if (!isSafeBackupAttachmentBlobName(blobName)) continue;
    if (blobName && !seen.has(blobName)) {
      seen.add(blobName);
      names.push(blobName);
    }
  }

  return names;
}

export async function importAndAuditRemoteBackupFile(
  env: Env,
  storage: StorageService,
  actorUserId: string,
  remoteFile: RemoteBackupFile,
  destination: BackupDestinationRecord,
  remotePath: string,
  replaceExisting: boolean,
  checksumMismatchAccepted: boolean,
  auditMetadata: Record<string, unknown> | null = null,
  targetDeviceIdentifier: string | null = null,
  keepAlive?: (() => Promise<void>) | null
): Promise<BackupImportExecutionResult> {
  const touchLease = async () => {
    await keepAlive?.();
  };
  const restoreFileName = remoteFile.fileName || remotePath.split('/').pop() || remotePath;
  await touchLease();
  const externalAttachmentBlobNames = collectExternalRemoteAttachmentBlobNames(remoteFile.bytes);
  const externalAttachmentCache = new Map<string, Uint8Array | null>();
  const progress: BackupRestoreProgressReporter = async (event) => {
    await touchLease();
    await notifyUserBackupRestoreProgress(
      env,
      actorUserId,
      {
        operation: 'backup-restore',
        ...event,
      },
      targetDeviceIdentifier
    );
  };
  const result = await importRemoteBackupArchiveBytes(
    remoteFile.bytes,
    env,
    actorUserId,
    replaceExisting,
    {
      loadAttachment: async (blobName) => {
        await touchLease();
        const normalized = String(blobName || '').trim();
        if (!normalized) return null;
        if (externalAttachmentCache.has(normalized)) {
          return externalAttachmentCache.get(normalized) || null;
        }

        const start = Math.max(0, externalAttachmentBlobNames.indexOf(normalized));
        const batchNames = externalAttachmentBlobNames
          .slice(start, start + REMOTE_ATTACHMENT_RESTORE_BATCH_SIZE)
          .filter((name) => !externalAttachmentCache.has(name));
        if (!batchNames.includes(normalized)) {
          batchNames.unshift(normalized);
        }

        try {
          const batch = await downloadRemoteAttachmentBatchViaDurableObject(env, destination, batchNames);
          for (const name of batchNames) {
            externalAttachmentCache.set(name, batch.get(name) || null);
          }
        } catch {
          externalAttachmentCache.set(normalized, await downloadRemoteAttachmentViaDurableObject(env, destination, normalized).catch(() => null));
        }
        await touchLease();
        return externalAttachmentCache.get(normalized) || null;
      },
    },
    progress,
    restoreFileName
  );
  await writeAuditLog(storage, result.auditActorUserId, 'admin.backup.import', 'backup', null, {
    users: result.result.imported.users,
    ciphers: result.result.imported.ciphers,
    attachments: result.result.imported.attachmentFiles,
    skippedAttachments: result.result.skipped.attachments,
    skippedReason: result.result.skipped.reason,
    replaceExisting,
    ...getBackupDestinationSummary(destination),
    remotePath,
    bytes: remoteFile.bytes.byteLength,
    trigger: 'remote',
    checksumMismatchAccepted,
    ...(auditMetadata || {}),
  });
  return result;
}

export async function restoreRemoteBackupInDurableObject(
  env: Env,
  payload: {
    actorUserId: string;
    allowChecksumMismatch?: boolean;
    auditMetadata?: Record<string, unknown> | null;
    destinationId?: string | null;
    path: string;
    replaceExisting?: boolean;
    targetDeviceIdentifier?: string | null;
  }
): Promise<BackupImportExecutionResult['result'] | null> {
  const response = await requestBackupTransferInternal(env, {
    name: 'configured-backup-runner',
    path: '/internal/restore-remote-backup',
    body: payload,
    errorPrefix: 'Remote backup restore failed',
    conflictStatus: 409,
  });
  if (!response) {
    return null;
  }
  return response.json<BackupImportExecutionResult['result']>();
}
