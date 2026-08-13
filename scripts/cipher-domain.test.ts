import assert from 'node:assert/strict';
import test from 'node:test';

import type { Attachment, Cipher } from '../src/types';
import {
  applyCipherEmbeddedAttachmentMetadata,
  cipherToResponse,
  formatAttachments,
  isCipherResponseSyncCompatible,
  normalizeCipherLoginForStorage,
  normalizeCipherSshKeyForCompatibility,
  validateCipherEncryptedFieldsForCompatibility,
} from '../src/services/cipher-domain';

const ENC = '0.iv|data'; // type-0 EncString: IV + ciphertext
const ENC2 = '0.iv2|data2';
const ENC3 = '0.iv3|data3';

function baseCipher(overrides: Partial<Cipher> = {}): Cipher {
  return {
    id: 'c1',
    userId: 'u1',
    organizationId: null,
    type: 1,
    name: ENC,
    notes: null,
    folderId: null,
    favorite: false,
    reprompt: 0,
    key: ENC,
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: null,
    passwordHistory: null,
    collectionIds: [],
    deletedAt: null,
    archivedAt: null,
    createdAt: new Date(1_700_000_000_000).toISOString(),
    updatedAt: new Date(1_700_000_000_001).toISOString(),
    ...overrides,
  } as unknown as Cipher;
}

// ---------------------------------------------------------------------------
// normalizeCipherLoginForStorage
// ---------------------------------------------------------------------------

test('cipher login normalize: keeps fido2Credentials array, nulls others', () => {
  assert.equal(normalizeCipherLoginForStorage(null), null);
  assert.deepEqual(normalizeCipherLoginForStorage({ username: ENC, fido2Credentials: [{ id: 'x' }] }), {
    username: ENC,
    fido2Credentials: [{ id: 'x' }],
  });
  assert.deepEqual(normalizeCipherLoginForStorage({ username: ENC, fido2Credentials: 'nope' }), {
    username: ENC,
    fido2Credentials: null,
  });
});

// ---------------------------------------------------------------------------
// normalizeCipherSshKeyForCompatibility
// ---------------------------------------------------------------------------

test('cipher ssh key normalize: keyFingerprint alias and trimming', () => {
  assert.equal(normalizeCipherSshKeyForCompatibility(null), null);
  assert.equal(normalizeCipherSshKeyForCompatibility({ privateKey: 'plain', publicKey: ENC, keyFingerprint: ENC }), null);
  const result = normalizeCipherSshKeyForCompatibility({ privateKey: ` ${ENC} `, publicKey: ENC2, fingerprint: ENC3 });
  assert.deepEqual(result, {
    privateKey: ENC,
    publicKey: ENC2,
    keyFingerprint: ENC3,
    fingerprint: ENC3,
  });
});

// ---------------------------------------------------------------------------
// validateCipherEncryptedFieldsForCompatibility
// ---------------------------------------------------------------------------

test('cipher validate: valid cipher passes', () => {
  assert.equal(validateCipherEncryptedFieldsForCompatibility(baseCipher()), null);
});

test('cipher validate: rejects plaintext name, notes, login fields', () => {
  assert.match(validateCipherEncryptedFieldsForCompatibility(baseCipher({ name: 'plain' }))!, /name/);
  assert.match(validateCipherEncryptedFieldsForCompatibility(baseCipher({ notes: 'plain' }))!, /notes/);
  const withLogin = baseCipher({ login: { username: 'plain', password: ENC, totp: ENC, uri: ENC } } as any);
  assert.match(validateCipherEncryptedFieldsForCompatibility(withLogin)!, /username/);
});

test('cipher validate: rejects plaintext ssh key and typed fields', () => {
  const badSsh = baseCipher({ sshKey: { privateKey: 'plain', publicKey: ENC, keyFingerprint: ENC } } as any);
  assert.match(validateCipherEncryptedFieldsForCompatibility(badSsh)!, /SSH key/);
  const badBank = baseCipher({ type: 6, bankAccount: { accountNumber: 'plain' } } as any);
  assert.match(validateCipherEncryptedFieldsForCompatibility(badBank)!, /Bank account/);
  const badHistory = baseCipher({ passwordHistory: [{ password: 'plain' }] } as any);
  assert.match(validateCipherEncryptedFieldsForCompatibility(badHistory)!, /Password history/);
});

// ---------------------------------------------------------------------------
// formatAttachments
// ---------------------------------------------------------------------------

test('cipher format attachments: empty -> null, size as string, url built', () => {
  assert.equal(formatAttachments([]), null);
  const formatted = formatAttachments([
    { id: 'a1', cipherId: 'c1', fileName: ENC, size: 1024, sizeName: '1 KB', key: null } as unknown as Attachment,
    { id: 'a2', cipherId: 'c1', fileName: 'plain', size: 0, sizeName: null, key: null } as unknown as Attachment,
  ])!;
  assert.equal(formatted.length, 1);
  assert.equal(formatted[0].id, 'a1');
  assert.equal(formatted[0].size, '1024');
  assert.equal(formatted[0].url, '/api/ciphers/c1/attachment/a1');
});

// ---------------------------------------------------------------------------
// cipherToResponse
// ---------------------------------------------------------------------------

test('cipher to response: strips internal fields, shapes server fields', () => {
  const cipher = baseCipher({ type: 1, key: ENC, name: ` ${ENC} ` });
  const response = cipherToResponse(cipher);
  assert.equal(response.object, 'cipherDetails');
  assert.equal(response.name, ENC);
  assert.equal(response.creationDate, cipher.createdAt);
  assert.equal(response.revisionDate, cipher.updatedAt);
  assert.equal(response.deletedDate, null);
  assert.equal(response.archivedDate, null);
  assert.equal(response.edit, true);
  assert.equal(response.viewPassword, true);
  assert.deepEqual(response.permissions, { delete: true, restore: true });
  assert.equal((response as any).userId, undefined);
  assert.equal((response as any).createdAt, undefined);
});

test('cipher to response: unknown passthrough fields survive', () => {
  const cipher = baseCipher({ type: 1, customFutureField: { x: 1 } } as any);
  assert.deepEqual((cipherToResponse(cipher) as any).customFutureField, { x: 1 });
});

test('cipher to response: folderId filtered by validFolderIds', () => {
  const cipher = baseCipher({ type: 1, folderId: 'f1' });
  assert.equal(cipherToResponse(cipher, [], { validFolderIds: new Set(['f1']) }).folderId, 'f1');
  assert.equal(cipherToResponse(cipher, [], { validFolderIds: new Set(['other']) }).folderId, null);
});

test('cipher to response: typed fields only for their type', () => {
  const bank = baseCipher({ type: 6, bankAccount: { accountNumber: ENC } } as any);
  const response = cipherToResponse(bank);
  assert.ok(response.bankAccount);
  assert.equal(response.driversLicense, null);
  assert.equal(response.passport, null);
  assert.equal(cipherToResponse(baseCipher({ type: 1, bankAccount: { accountNumber: ENC } } as any)).bankAccount, null);
});

test('cipher to response: sync compatibility requires encrypted name', () => {
  assert.equal(isCipherResponseSyncCompatible(cipherToResponse(baseCipher({ type: 1 }))), true);
  assert.equal(isCipherResponseSyncCompatible(cipherToResponse(baseCipher({ type: 1, name: 'plain' }))), false);
});

// ---------------------------------------------------------------------------
// applyCipherEmbeddedAttachmentMetadata
// ---------------------------------------------------------------------------

test('cipher attachment metadata: merges embedded fileName/key/size', () => {
  const attachments = [
    { id: 'a1', cipherId: 'c1', fileName: ENC, size: 1, sizeName: '1 Bytes', key: null },
  ] as unknown as Attachment[];
  const updated = applyCipherEmbeddedAttachmentMetadata(
    { attachments2: [{ Id: 'a1', FileName: ENC2, Key: ENC3, FileSize: 2048 }] },
    attachments
  );
  assert.equal(updated[0].fileName, ENC2);
  assert.equal(updated[0].key, ENC3);
  assert.equal(updated[0].size, 2048);
  assert.equal(updated[0].sizeName, '2.00 KB');
});
