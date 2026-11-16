import { randomUUID } from 'node:crypto';
import { appendAudit } from './audit.js';
import { tx } from './db.js';
import { badRequest, HttpError } from './http.js';
import { DOCUMENT_TYPES, validateAccess, validateDocumentName } from './passports.js';

/**
 * Validates and stores a document for a passport OR a model (exactly one).
 * Model documents are stored once and shown on every passport of the model.
 */
const TYPE_BY_EXTENSION = {
  pdf: 'application/pdf',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  json: 'application/json',
  csv: 'text/csv',
  txt: 'text/plain',
};

/**
 * The declared type when it is allowed, otherwise the type implied by the
 * file extension (browsers on Windows report .csv as an Excel type, some
 * report nothing at all). The content check below still applies.
 */
export function resolveType(contentType, name) {
  const declared = (contentType ?? '').split(';')[0].trim().toLowerCase();
  if (DOCUMENT_TYPES[declared]) return declared;
  const ext = String(name ?? '').toLowerCase().split('.').pop();
  return TYPE_BY_EXTENSION[ext] ?? declared;
}

export async function storeDocument(db, blobs, { tenant, passportId = null, modelId = null, name, access, contentType, buf }) {
  const cleanName = validateDocumentName(name);
  const cleanAccess = validateAccess(access ?? 'public');
  const type = resolveType(contentType, cleanName);
  const sniff = DOCUMENT_TYPES[type];
  if (!sniff) {
    throw new HttpError(415, 'unsupported_media_type', `Allowed types: ${Object.keys(DOCUMENT_TYPES).join(', ')}`);
  }
  if (!buf.length) throw badRequest('Document is empty');
  if (!sniff(buf)) throw badRequest(`File content does not match type ${type}`);

  const hash = await blobs.put(buf);
  const id = randomUUID();
  const now = new Date().toISOString();
  return tx(db, async (t) => {
    await t.docInsert.run(id, passportId, modelId, cleanName, type, buf.length, hash, cleanAccess, now, null);
    if (passportId) await t.passportTouch.run(now, passportId);
    else await t.modelTouch.run(now, modelId);
    await appendAudit(t, {
      actor: tenant.actor,
      action: 'document.added',
      target: passportId ?? modelId,
      details: { documentId: id, sha256: hash, access: cleanAccess, scope: passportId ? 'passport' : 'model' },
    });
    return passportId ? t.docGet.get(id, passportId) : t.modelDocGet.get(id, modelId);
  });
}

/**
 * Finds the battery a file belongs to from its name: "BAT-0001.pdf" or
 * "BAT-0001_test-report.pdf" (or "BAT-0001 test report.pdf") -> "BAT-0001".
 * Tries the whole name first, so identifiers containing "_" still work.
 */
export async function matchBatteryByFileName(st, tenantId, fileName) {
  const stem = String(fileName).replace(/\.[^.]+$/, '').trim();
  const candidates = [stem];
  for (const sep of ['_', ' ']) {
    const i = stem.indexOf(sep);
    if (i > 0) candidates.push(stem.slice(0, i));
  }
  for (const candidate of [...new Set(candidates)]) {
    const hit = await st.passportFindByIdentifier.get(tenantId, candidate);
    if (hit) return { passportId: hit.id, productIdentifier: candidate };
  }
  return null;
}

export async function removeDocument(db, { tenant, passportId = null, modelId = null, documentId }) {
  const now = new Date().toISOString();
  const removed = await tx(db, async (t) => {
    const r = passportId
      ? await t.docRemove.run(now, documentId, passportId)
      : await t.modelDocRemove.run(now, documentId, modelId);
    if (!r.changes) return false;
    if (passportId) await t.passportTouch.run(now, passportId);
    else await t.modelTouch.run(now, modelId);
    await appendAudit(t, { actor: tenant.actor, action: 'document.removed', target: passportId ?? modelId, details: { documentId } });
    return true;
  });
  // The file itself is kept: removal hides it but the history stays auditable.
  if (!removed) throw new HttpError(404, 'document_not_found', 'Document not found');
}
