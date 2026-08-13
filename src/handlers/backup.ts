import type { Env, User } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import {
  type BackupArchiveBundle,
  MAX_BACKUP_ARCHIVE_BYTES,
  buildBackupArchive,
  inspectBackupArchiveFileNameChecksum,
  isSafeBackupAttachmentBlobName,
  verifyBackupArchiveFileNameChecksum,
} from '../services/backup-archive';
import {
  type BackupSettingsInput,
  getBackupSettingsRepairState,
  getDefaultBackupSettings,
  loadBackupSettings,
  normalizeBackupSettingsInput,
  normalizeImportedBackupSettings,
  redactBackupSettingsSecrets,
  repairBackupSettings,
  requireBackupDestination,
  saveBackupSettings,
} from '../services/backup-config';
import {
  type BackupImportExecutionResult,
  type BackupRestoreProgressReporter,
  importBackupArchiveBytes,
} from '../services/backup-import';
import {
  deleteRemoteBackupFile,
  downloadRemoteBackupFile,
  ensureRemoteRestoreCandidate,
  listRemoteBackupEntries,
} from '../services/backup-uploader';
import {
  getBackupDestinationSummary,
  restoreRemoteBackupInDurableObject,
  runConfiguredBackupInDurableObject,
  runScheduledBackupsInDurableObject,
  writeAuditLog,
} from '../services/backup-runner';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { auditRequestMetadata } from '../services/audit-events';
import { getBlobObject } from '../services/blob-store';
import { notifyUserBackupProgress, notifyUserBackupRestoreProgress } from '../durable/notifications-hub';
import { getMultipartRequestMaxBytes } from '../utils/direct-upload';
import { verifyPasskeyUserVerificationToken } from '../utils/user-verification-token';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

function parseRequestContentLength(request: Request): number | null {
  const raw = request.headers.get('content-length');
  if (!raw) return null;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) return null;
  return Math.floor(value);
}

async function requireBackupUserVerification(actorUser: User, masterPasswordHash: string, env: Env): Promise<Response | null> {
  const normalized = String(masterPasswordHash || '').trim();
  if (!normalized) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const auth = new AuthService(env);
  const valid = await auth.verifyPassword(normalized, actorUser.masterPasswordHash, actorUser.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }
  return null;
}

async function requireBackupRepairVerification(
  actorUser: User,
  body: { masterPasswordHash?: string; userVerificationToken?: string },
  env: Env
): Promise<Response | null> {
  const masterPasswordHash = String(body.masterPasswordHash || '').trim();
  if (masterPasswordHash) {
    return requireBackupUserVerification(actorUser, masterPasswordHash, env);
  }

  const userVerificationToken = String(body.userVerificationToken || '').trim();
  if (!userVerificationToken) {
    return errorResponse('masterPasswordHash or userVerificationToken is required', 400);
  }
  const valid = await verifyPasskeyUserVerificationToken(env, userVerificationToken, actorUser.id, 'backup.settings.repair');
  if (!valid) {
    return errorResponse('Invalid user verification token', 400);
  }
  return null;
}

function ensureBackupBlobName(value: string): string {
  const normalized = String(value || '').trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!normalized) {
    throw new Error('Backup attachment blob is required');
  }
  if (!isSafeBackupAttachmentBlobName(normalized)) {
    throw new Error('Backup attachment blob is invalid');
  }
  return normalized;
}

function contentDispositionBackup(fileName: string | null | undefined): string {
  const fallback = 'nodewarden_backup.zip';
  const value = String(fileName || fallback)
    .replace(/[\\/\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

function toImportStatusCode(message: string): number {
  const lower = message.toLowerCase();
  if (lower.includes('checksum')) return 400;
  if (lower.includes('invalid remote backup path') || lower.includes('please select a backup zip file')) return 409;
  if (lower.includes('invalid backup') || lower.includes('invalid json')) return 400;
  if (lower.includes('fresh instance')) return 409;
  if (lower.includes('not configured') || lower.includes('kv')) return 409;
  return 500;
}

async function runImportAndAudit(
  env: Env,
  request: Request,
  actorUser: User,
  archiveBytes: Uint8Array,
  fileName: string,
  replaceExisting: boolean,
  metadata: Record<string, unknown>
): Promise<BackupImportExecutionResult> {
  const storage = new StorageService(env.DB);
  const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
  const progress: BackupRestoreProgressReporter = async (event) => {
    await notifyUserBackupRestoreProgress(
      env,
      actorUser.id,
      {
        operation: 'backup-restore',
        ...event,
      },
      targetDeviceIdentifier
    );
  };
  await progress({
    source: 'local',
    step: 'local_upload_received',
    fileName,
    stageTitle: 'txt_backup_restore_progress_local_upload_title',
    stageDetail: 'txt_backup_restore_progress_local_upload_detail',
    replaceExisting,
  });
  const imported = await importBackupArchiveBytes(archiveBytes, env, actorUser.id, replaceExisting, progress, fileName);
  await writeAuditLog(storage, imported.auditActorUserId, 'admin.backup.import', 'backup', null, {
    users: imported.result.imported.users,
    ciphers: imported.result.imported.ciphers,
    attachments: imported.result.imported.attachmentFiles,
    skippedAttachments: imported.result.skipped.attachments,
    skippedReason: imported.result.skipped.reason,
    replaceExisting,
    ...metadata,
  }, request);
  return imported;
}

export async function runScheduledBackupIfDue(env: Env): Promise<void> {
  await runScheduledBackupsInDurableObject(env);
}

export async function handleGetAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    return jsonResponse(redactBackupSettingsSecrets(settings));
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings could not be loaded', 409);
  }
}

export async function handleUpdateAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: BackupSettingsInput & { masterPasswordHash?: string };
  try {
    body = await request.json<BackupSettingsInput & { masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Backup settings payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  let previous;
  try {
    previous = await loadBackupSettings(storage, env, 'UTC');
  } catch {
    previous = getDefaultBackupSettings('UTC');
  }

  let next;
  try {
    next = normalizeBackupSettingsInput(body, previous);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings are invalid', 400);
  }

  await saveBackupSettings(storage, env, next);
  await writeAuditLog(storage, actorUser.id, 'admin.backup.settings.update', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  }, request);
  return jsonResponse(redactBackupSettingsSecrets(next));
}

export async function handleGetAdminBackupSettingsRepairState(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const state = await getBackupSettingsRepairState(storage, env, 'UTC');
    return jsonResponse({
      object: 'backup-settings-repair',
      needsRepair: state.needsRepair,
      portable: state.portable,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings repair state could not be loaded', 409);
  }
}

export async function handleRepairAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: BackupSettingsInput & { masterPasswordHash?: string; userVerificationToken?: string };
  try {
    body = await request.json<BackupSettingsInput & { masterPasswordHash?: string; userVerificationToken?: string }>();
  } catch {
    return errorResponse('Backup settings repair payload is invalid', 400);
  }

  const verificationError = await requireBackupRepairVerification(actorUser, body, env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  let previous;
  try {
    previous = await loadBackupSettings(storage, env, 'UTC');
  } catch {
    previous = getDefaultBackupSettings('UTC');
  }

  let next;
  try {
    next = normalizeBackupSettingsInput(body, previous);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings repair payload is invalid', 400);
  }

  await repairBackupSettings(storage, env, next);
  await writeAuditLog(storage, actorUser.id, 'admin.backup.settings.repair', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  }, request);
  return jsonResponse(redactBackupSettingsSecrets(next));
}

export async function handleRunAdminConfiguredBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    let body: { destinationId?: string; masterPasswordHash?: string } | null = null;
    try {
      if ((request.headers.get('Content-Type') || '').includes('application/json')) {
        body = await request.json<{ destinationId?: string; masterPasswordHash?: string }>();
      }
    } catch {
      return errorResponse('Backup run payload is invalid', 400);
    }

    const verificationError = await requireBackupUserVerification(actorUser, String(body?.masterPasswordHash || ''), env);
    if (verificationError) return verificationError;

    const outcome = await runConfiguredBackupInDurableObject(env, {
      actorUserId: actorUser.id,
      auditMetadata: auditRequestMetadata(request),
      destinationId: body?.destinationId || null,
      targetDeviceIdentifier: String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null,
      trigger: 'manual',
    });
    if (!outcome) {
      return errorResponse('Another backup run is already in progress', 409);
    }
    return jsonResponse({
      object: 'backup-run',
      result: {
        fileName: outcome.result.fileName,
        fileSize: outcome.result.fileSize,
        provider: outcome.result.provider,
        remotePath: outcome.result.remotePath,
      },
      settings: redactBackupSettingsSecrets(outcome.settings),
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup run failed', 500);
  }
}

export async function handleListAdminRemoteBackups(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const url = new URL(request.url);
    const destination = requireBackupDestination(settings, url.searchParams.get('destinationId') || null);
    const listing = await listRemoteBackupEntries(destination, url.searchParams.get('path') || '');
    return jsonResponse({
      object: 'backup-remote-browser',
      destinationId: destination.id,
      destinationName: destination.name,
      ...listing,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup listing failed', 409);
  }
}

export async function handleDownloadAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: { destinationId?: string; path?: string; masterPasswordHash?: string };
  try {
    body = await request.json<{ destinationId?: string; path?: string; masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Remote backup download payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const destination = requireBackupDestination(settings, body.destinationId || null);
    const remoteFile = await downloadRemoteBackupFile(destination, path);
    return new Response(remoteFile.bytes, {
      status: 200,
      headers: {
        'Content-Type': remoteFile.contentType || 'application/zip',
        'Content-Disposition': contentDispositionBackup(remoteFile.fileName),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup download failed', 409);
  }
}

export async function handleInspectAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: { destinationId?: string; path?: string; masterPasswordHash?: string };
  try {
    body = await request.json<{ destinationId?: string; path?: string; masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Remote backup integrity payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const destination = requireBackupDestination(settings, body.destinationId || null);
    const remoteFile = await downloadRemoteBackupFile(destination, path);
    const integrity = await inspectBackupArchiveFileNameChecksum(remoteFile.bytes, remoteFile.fileName || path);
    return jsonResponse({
      object: 'backup-remote-integrity',
      destinationId: destination.id,
      path,
      fileName: remoteFile.fileName || path.split('/').pop() || path,
      integrity,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup integrity inspection failed', 409);
  }
}

export async function handleDeleteAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: { destinationId?: string; path?: string; masterPasswordHash?: string };
  try {
    body = await request.json<{ destinationId?: string; path?: string; masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Remote backup delete payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const destination = requireBackupDestination(settings, body.destinationId || null);
    await deleteRemoteBackupFile(destination, path);
    await writeAuditLog(storage, actorUser.id, 'admin.backup.remote.delete', 'backup', null, {
      ...getBackupDestinationSummary(destination),
      remotePath: path,
    }, request);
    return jsonResponse({ object: 'backup-remote-delete', deleted: true, path });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup delete failed', 409);
  }
}

export async function handleRestoreAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: {
    destinationId?: string;
    path?: string;
    replaceExisting?: boolean;
    allowChecksumMismatch?: boolean;
    masterPasswordHash?: string;
  };
  try {
    body = await request.json<{ destinationId?: string; path?: string; replaceExisting?: boolean }>();
  } catch {
    return errorResponse('Remote restore payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  try {
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
    const imported = await restoreRemoteBackupInDurableObject(env, {
      actorUserId: actorUser.id,
      allowChecksumMismatch: !!body.allowChecksumMismatch,
      auditMetadata: auditRequestMetadata(request),
      destinationId: body.destinationId || null,
      path,
      replaceExisting: !!body.replaceExisting,
      targetDeviceIdentifier,
    });
    if (!imported) {
      return errorResponse('Another backup or restore run is already in progress', 409);
    }
    return jsonResponse(imported);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Remote backup restore failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function handleAdminExportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
  let body: { includeAttachments?: boolean; masterPasswordHash?: string } | null = null;
  try {
    if ((request.headers.get('Content-Type') || '').includes('application/json')) {
      body = await request.json<{ includeAttachments?: boolean; masterPasswordHash?: string }>();
    }
  } catch {
    return errorResponse('Backup export payload is invalid', 400);
  }
  const verificationError = await requireBackupUserVerification(actorUser, String(body?.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;
  let archive: BackupArchiveBundle;
  try {
    const progress = async (event: {
      step: string;
      fileName?: string;
      stageTitle: string;
      stageDetail: string;
      includeAttachments: boolean;
    }) => {
      await notifyUserBackupProgress(
        env,
        actorUser.id,
        {
          operation: 'backup-export',
          source: 'local',
          step: `export_${event.step}`,
          fileName: event.fileName || '',
          stageTitle: event.stageTitle,
          stageDetail: event.stageDetail,
        },
        targetDeviceIdentifier
      );
    };
    archive = await buildBackupArchive(env, new Date(), {
      includeAttachments: !!body?.includeAttachments,
      progress,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup export failed';
    await notifyUserBackupProgress(
      env,
      actorUser.id,
      {
        operation: 'backup-export',
        source: 'local',
        step: 'export_failed',
        fileName: '',
        stageTitle: 'txt_backup_export_progress_failed_title',
        stageDetail: 'txt_backup_export_progress_failed_detail',
        done: true,
        ok: false,
        error: message,
      },
      targetDeviceIdentifier
    );
    return errorResponse(message, message.includes('blob missing') ? 409 : 500);
  }

  await writeAuditLog(storage, actorUser.id, 'admin.backup.export', 'backup', null, {
    users: archive.manifest.tableCounts.users,
    ciphers: archive.manifest.tableCounts.ciphers,
    attachments: archive.manifest.tableCounts.attachments,
    compressedBytes: archive.bytes.byteLength,
    includesAttachments: archive.manifest.includes.attachments,
  }, request);

  return new Response(archive.bytes, {
    status: 200,
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': contentDispositionBackup(archive.fileName),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function handleDownloadAdminBackupAttachment(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    // Read the request body only. Accepting these fields from the query string
    // would put the master-password authentication hash in the URL, where it is
    // captured by request logs, browser history and Referer headers.
    let input: { blobName?: unknown; masterPasswordHash?: unknown };
    try {
      input = await request.json<{ blobName?: unknown; masterPasswordHash?: unknown }>();
    } catch {
      return errorResponse('Backup attachment download payload is invalid', 400);
    }

    const verificationError = await requireBackupUserVerification(
      actorUser,
      String(input.masterPasswordHash || ''),
      env
    );
    if (verificationError) return verificationError;

    const blobName = ensureBackupBlobName(String(input.blobName || ''));
    const object = await getBlobObject(env, blobName);
    if (!object) {
      return errorResponse('Backup attachment blob not found', 404);
    }
    return new Response(object.body, {
      status: 200,
      headers: {
        'Content-Type': object.contentType || 'application/octet-stream',
        'Content-Length': String(object.size),
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup attachment download failed', 400);
  }
}

export async function handleAdminImportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.includes('multipart/form-data')) {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }
  const declaredSize = parseRequestContentLength(request);
  if (declaredSize !== null && declaredSize > getMultipartRequestMaxBytes(MAX_BACKUP_ARCHIVE_BYTES)) {
    return errorResponse(`Backup file too large. Maximum size is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))}MB`, 413);
  }

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }

  const file = formData.get('file');
  if (!file || typeof file !== 'object' || !('arrayBuffer' in file)) {
    return errorResponse('Backup file is required', 400);
  }
  if ('size' in file && typeof (file as File).size === 'number' && (file as File).size > MAX_BACKUP_ARCHIVE_BYTES) {
    return errorResponse(`Backup file too large. Maximum size is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))}MB`, 413);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(formData.get('masterPasswordHash') || ''), env);
  if (verificationError) return verificationError;

  const replaceExisting = String(formData.get('replaceExisting') || '').trim() === '1';
  const allowChecksumMismatch = String(formData.get('allowChecksumMismatch') || '').trim() === '1';
  let archiveBytes: Uint8Array;
  try {
    archiveBytes = new Uint8Array(await (file as { arrayBuffer(): Promise<ArrayBuffer> }).arrayBuffer());
  } catch {
    return errorResponse('Unable to read backup file', 400);
  }

  try {
    const fileName = 'name' in file ? String((file as File).name || '') : '';
    const checksumOk = await verifyBackupArchiveFileNameChecksum(archiveBytes, fileName);
    if (!checksumOk && !allowChecksumMismatch) {
      return errorResponse('Backup file checksum does not match its filename', 400);
    }
    const imported = await runImportAndAudit(env, request, actorUser, archiveBytes, fileName || 'nodewarden_backup.zip', replaceExisting, {
      trigger: 'local',
      bytes: archiveBytes.byteLength,
      checksumMismatchAccepted: !checksumOk,
    });
    return jsonResponse(imported.result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup import failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function seedDefaultBackupSettings(env: Env): Promise<void> {
  const storage = new StorageService(env.DB);
  const current = await storage.getConfigValue('backup.settings.v1');
  if (current) {
    await normalizeImportedBackupSettings(storage, env, 'UTC');
    return;
  }
  await saveBackupSettings(storage, env, getDefaultBackupSettings('UTC'));
}
