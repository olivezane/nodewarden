import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeBackupEndpointUrl } from '../src/services/backup-config';
import { isBackupArchiveName } from '../src/services/backup-uploader';

test('retention pruning only matches this app own archive names', () => {
  assert.equal(isBackupArchiveName('nodewarden_backup_20260101_101010.zip'), true);
  assert.equal(isBackupArchiveName('nodewarden_backup_20260101_101010_ab12c.zip'), true);
  assert.equal(isBackupArchiveName('nightly-db-dump.zip'), false);
  assert.equal(isBackupArchiveName('nodewarden_backup_20260101_101010.zip.bak'), false);
  assert.equal(isBackupArchiveName('prefix_nodewarden_backup_20260101_101010.zip'), false);
  assert.equal(isBackupArchiveName(''), false);
});

test('backup destinations reject cleartext http', () => {
  assert.throws(() => normalizeBackupEndpointUrl('http://example.com', 'WebDAV server URL'), /https:\/\//);
  assert.equal(normalizeBackupEndpointUrl('https://example.com/', 'WebDAV server URL'), 'https://example.com');
});
