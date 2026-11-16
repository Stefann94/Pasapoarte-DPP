import { randomUUID } from 'node:crypto';
import { appendAudit } from './audit.js';
import { sha256 } from './crypto.js';
import { isUniqueViolation, tx } from './db.js';
import { badRequest, HttpError, isPlainObject } from './http.js';
import {
  DOCUMENT_TYPES,
  hashData,
  normalizeData,
  validateAccess,
  validateDocumentName,
  validatePassportFields,
} from './passports.js';

export const EXPORT_FORMAT = 'dpp-hosting-export';
export const EXPORT_FORMAT_VERSION = 1;

/**
 * Self-contained, documented export format. Moving to another provider (or
 * restoring here) needs nothing but this file: passport ids are preserved so
 * QR codes keep resolving once the domain points to the new host.
 */
export async function buildExport(st, blobs, config, tenant, { includeDocuments = true } = {}) {
  const passports = [];
  for (const p of st.passportAllForTenant.all(tenant.tenantId)) {
    const documents = [];
    for (const d of st.docAll.all(p.id)) {
      const doc = {
        id: d.id,
        name: d.name,
        contentType: d.content_type,
        size: d.size,
        sha256: d.sha256,
        access: d.access,
        createdAt: d.created_at,
        removedAt: d.removed_at,
      };
      if (includeDocuments) doc.contentBase64 = (await blobs.get(d.sha256)).toString('base64');
      documents.push(doc);
    }
    passports.push({
      id: p.id,
      productIdentifier: p.product_identifier,
      category: p.category,
      createdAt: p.created_at,
      currentVersion: p.current_version,
      versions: st.versionAll.all(p.id).map((v) => ({
        version: v.version,
        dataSha256: v.data_hash,
        note: v.note,
        createdAt: v.created_at,
        createdBy: v.created_by,
        data: JSON.parse(v.data),
      })),
      documents,
    });
  }
  return {
    format: EXPORT_FORMAT,
    formatVersion: EXPORT_FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    source: config.baseUrl,
    tenant: { id: tenant.tenantId, name: tenant.tenantName },
    passports,
  };
}

/** Validates one exported passport fully before anything is written. */
function preparePassport(p) {
  if (!isPlainObject(p)) throw badRequest('passport entry must be an object');
  validatePassportFields({ id: p.id, productIdentifier: p.productIdentifier, category: p.category });
  if (p.id === undefined) throw badRequest('passport id is required for import');
  if (!Array.isArray(p.versions) || !p.versions.length) throw badRequest('versions must be a non-empty array');

  const versions = p.versions.map((v, i) => {
    if (!isPlainObject(v) || v.version !== i + 1) throw badRequest('versions must be numbered 1, 2, 3, ... in order');
    const data = normalizeData(v.data);
    const dataSha256 = hashData(data);
    if (v.dataSha256 && v.dataSha256 !== dataSha256) {
      throw badRequest(`version ${v.version}: data does not match dataSha256 (corrupted export?)`);
    }
    return { version: v.version, data, dataSha256, note: typeof v.note === 'string' ? v.note : null, createdAt: String(v.createdAt ?? new Date().toISOString()) };
  });

  const documents = (Array.isArray(p.documents) ? p.documents : []).map((d) => {
    if (!isPlainObject(d) || typeof d.contentBase64 !== 'string') {
      throw badRequest('every document must include contentBase64 (export with includeDocuments=1)');
    }
    const buf = Buffer.from(d.contentBase64, 'base64');
    if (sha256(buf) !== d.sha256) throw badRequest(`document ${d.id}: content does not match sha256`);
    if (!DOCUMENT_TYPES[d.contentType]) throw badRequest(`document ${d.id}: unsupported contentType`);
    return {
      id: typeof d.id === 'string' && d.id.length <= 128 ? d.id : randomUUID(),
      name: validateDocumentName(d.name),
      contentType: d.contentType,
      access: validateAccess(d.access),
      createdAt: String(d.createdAt ?? new Date().toISOString()),
      removedAt: d.removedAt ? String(d.removedAt) : null,
      buf,
    };
  });

  return { id: p.id, productIdentifier: p.productIdentifier, category: p.category, createdAt: String(p.createdAt ?? versions[0].createdAt), versions, documents };
}

export async function importBundle(db, st, blobs, tenant, bundle) {
  if (bundle.format !== EXPORT_FORMAT || bundle.formatVersion !== EXPORT_FORMAT_VERSION) {
    throw badRequest(`Expected format "${EXPORT_FORMAT}" version ${EXPORT_FORMAT_VERSION}`);
  }
  if (!Array.isArray(bundle.passports)) throw badRequest('passports must be an array');

  const actor = `key:${tenant.keyId}`;
  const results = [];
  for (const raw of bundle.passports) {
    const id = isPlainObject(raw) ? raw.id : undefined;
    try {
      const p = preparePassport(raw);
      if (st.passportById.get(p.id)) {
        results.push({ id, status: 'skipped', reason: 'A passport with this id already exists' });
        continue;
      }
      for (const d of p.documents) d.sha256 = await blobs.put(d.buf);
      const last = p.versions.at(-1);
      tx(db, () => {
        st.passportInsert.run(p.id, tenant.tenantId, p.productIdentifier, p.category, last.version, p.createdAt, last.createdAt);
        for (const v of p.versions) {
          st.versionInsert.run(p.id, v.version, JSON.stringify(v.data), v.dataSha256, v.note, v.createdAt, `import:${tenant.keyId}`);
        }
        for (const d of p.documents) {
          st.docInsert.run(d.id, p.id, d.name, d.contentType, d.buf.length, d.sha256, d.access, d.createdAt, d.removedAt);
        }
        appendAudit(st, {
          actor,
          action: 'passport.imported',
          target: p.id,
          details: { versions: p.versions.length, documents: p.documents.length, source: String(bundle.source ?? '') },
        });
      });
      results.push({ id, status: 'imported', versions: p.versions.length, documents: p.documents.length });
    } catch (err) {
      if (err instanceof HttpError) results.push({ id, status: 'error', message: err.message });
      else if (isUniqueViolation(err)) results.push({ id, status: 'error', message: 'Conflicting id or productIdentifier' });
      else throw err;
    }
  }
  const count = (s) => results.filter((r) => r.status === s).length;
  return { imported: count('imported'), skipped: count('skipped'), errors: count('error'), results };
}
