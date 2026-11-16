import { randomUUID } from 'node:crypto';
import { appendAudit } from './audit.js';
import { tx } from './db.js';
import { badRequest, HttpError } from './http.js';
import { DOCUMENT_TYPES, validateAccess, validateDocumentName } from './passports.js';

/**
 * Validates and stores a document for a passport OR a model (exactly one).
 * Model documents are stored once and shown on every passport of the model.
 */
export async function storeDocument(db, blobs, { tenant, passportId = null, modelId = null, name, access, contentType, buf }) {
  const cleanName = validateDocumentName(name);
  const cleanAccess = validateAccess(access ?? 'public');
  const type = (contentType ?? '').split(';')[0].trim().toLowerCase();
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
