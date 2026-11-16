import { randomUUID } from 'node:crypto';
import { appendAudit } from './audit.js';
import { sha256 } from './crypto.js';
import { isUniqueViolation, tx } from './db.js';
import { badRequest, HttpError, isPlainObject } from './http.js';
import { validateExternalUrl } from './mirror.js';
import {
  CATEGORIES,
  DOCUMENT_TYPES,
  hashData,
  normalizeData,
  validateAccess,
  validateDocumentName,
  validateModelName,
  validatePassportFields,
} from './passports.js';

export const EXPORT_FORMAT = 'dpp-hosting-export';
export const EXPORT_FORMAT_VERSION = 2; // v2 adds models; v1 bundles are still importable

/**
 * Self-contained, documented export format. Moving to another provider (or
 * restoring here) needs nothing but this file: model and passport ids are
 * preserved so QR codes keep resolving once the domain points to the new host.
 */
export async function buildExport(st, blobs, config, tenant, { includeDocuments = true } = {}) {
  const exportDocs = async (rows) => {
    const out = [];
    for (const d of rows) {
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
      out.push(doc);
    }
    return out;
  };
  const versionsOf = (rows) =>
    rows.map((v) => ({
      version: v.version,
      dataSha256: v.data_hash,
      note: v.note,
      createdAt: v.created_at,
      createdBy: v.created_by,
      data: JSON.parse(v.data),
    }));

  const models = [];
  for (const m of await st.modelAllForTenant.all(tenant.tenantId)) {
    models.push({
      id: m.id,
      name: m.name,
      category: m.category,
      createdAt: m.created_at,
      currentVersion: m.current_version,
      versions: versionsOf(await st.modelVersionAll.all(m.id)),
      documents: await exportDocs(await st.modelDocAll.all(m.id)),
    });
  }

  const passports = [];
  for (const p of await st.passportAllForTenant.all(tenant.tenantId)) {
    passports.push({
      id: p.id,
      productIdentifier: p.product_identifier,
      category: p.category,
      modelId: p.model_id ?? null,
      externalUrl: p.external_url ?? null,
      createdAt: p.created_at,
      currentVersion: p.current_version,
      versions: versionsOf(await st.versionAll.all(p.id)),
      documents: await exportDocs(await st.docAll.all(p.id)),
    });
  }
  return {
    format: EXPORT_FORMAT,
    formatVersion: EXPORT_FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    source: config.baseUrl,
    tenant: { id: tenant.tenantId, name: tenant.tenantName },
    models,
    passports,
  };
}

function prepareVersions(list) {
  if (!Array.isArray(list) || !list.length) throw badRequest('versions must be a non-empty array');
  return list.map((v, i) => {
    if (!isPlainObject(v) || v.version !== i + 1) throw badRequest('versions must be numbered 1, 2, 3, ... in order');
    const data = normalizeData(v.data);
    const dataSha256 = hashData(data);
    if (v.dataSha256 && v.dataSha256 !== dataSha256) {
      throw badRequest(`version ${v.version}: data does not match dataSha256 (corrupted export?)`);
    }
    return {
      version: v.version,
      data,
      dataSha256,
      note: typeof v.note === 'string' ? v.note : null,
      createdAt: String(v.createdAt ?? new Date().toISOString()),
    };
  });
}

function prepareDocuments(list) {
  return (Array.isArray(list) ? list : []).map((d) => {
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
}

const storeBlobs = async (blobs, docs) => {
  for (const d of docs) d.sha256 = await blobs.put(d.buf);
};

const insertDocs = async (t, docs, passportId, modelId) => {
  for (const d of docs) {
    await t.docInsert.run(d.id, passportId, modelId, d.name, d.contentType, d.buf.length, d.sha256, d.access, d.createdAt, d.removedAt);
  }
};

export async function importBundle(db, st, blobs, tenant, bundle) {
  if (bundle.format !== EXPORT_FORMAT || ![1, 2].includes(bundle.formatVersion)) {
    throw badRequest(`Expected format "${EXPORT_FORMAT}" version 1 or 2`);
  }
  if (!Array.isArray(bundle.passports)) throw badRequest('passports must be an array');
  const models = Array.isArray(bundle.models) ? bundle.models : [];
  const { actor } = tenant;
  const results = [];
  const record = (kind, id, status, extra = {}) => results.push({ kind, id, status, ...extra });
  const fail = (kind, id, err) => {
    if (err instanceof HttpError) record(kind, id, 'error', { message: err.message });
    else if (isUniqueViolation(err)) record(kind, id, 'error', { message: 'Conflicting id, name or productIdentifier' });
    else throw err;
  };

  // Models first: passports reference them.
  const importedModels = new Set();
  for (const raw of models) {
    const id = isPlainObject(raw) ? raw.id : undefined;
    try {
      if (typeof id !== 'string' || !id || id.length > 128) throw badRequest('model id is required');
      const name = validateModelName(raw.name);
      if (!CATEGORIES.includes(raw.category)) throw badRequest('invalid model category');
      const versions = prepareVersions(raw.versions);
      const documents = prepareDocuments(raw.documents);
      const existing = await st.modelById.get(id);
      if (existing) {
        if (existing.tenant_id === tenant.tenantId) importedModels.add(id);
        record('model', id, 'skipped', { reason: 'A model with this id already exists' });
        continue;
      }
      await storeBlobs(blobs, documents);
      const last = versions.at(-1);
      await tx(db, async (t) => {
        await t.modelInsert.run(id, tenant.tenantId, name, raw.category, String(raw.createdAt ?? versions[0].createdAt));
        for (const v of versions) {
          await t.modelVersionInsert.run(id, v.version, JSON.stringify(v.data), v.dataSha256, v.note, v.createdAt, `import:${actor}`);
        }
        if (last.version > 1) await t.modelBump.run(last.version, last.createdAt, id);
        await insertDocs(t, documents, null, id);
        await appendAudit(t, { actor, action: 'model.imported', target: id, details: { versions: versions.length, documents: documents.length } });
      });
      importedModels.add(id);
      record('model', id, 'imported', { versions: versions.length, documents: documents.length });
    } catch (err) {
      fail('model', id, err);
    }
  }

  for (const raw of bundle.passports) {
    const id = isPlainObject(raw) ? raw.id : undefined;
    try {
      if (!isPlainObject(raw)) throw badRequest('passport entry must be an object');
      validatePassportFields({ id: raw.id, productIdentifier: raw.productIdentifier, category: raw.category });
      if (raw.id === undefined) throw badRequest('passport id is required for import');
      const modelId = raw.modelId ?? null;
      if (modelId && !importedModels.has(modelId)) throw badRequest(`model ${modelId} is not part of this import`);
      const externalUrl = raw.externalUrl ? validateExternalUrl(raw.externalUrl, { allowInsecure: true }) : null;
      const versions = prepareVersions(raw.versions);
      const documents = prepareDocuments(raw.documents);
      if (await st.passportById.get(raw.id)) {
        record('passport', id, 'skipped', { reason: 'A passport with this id already exists' });
        continue;
      }
      await storeBlobs(blobs, documents);
      const last = versions.at(-1);
      await tx(db, async (t) => {
        await t.passportInsert.run(raw.id, tenant.tenantId, raw.productIdentifier, raw.category, last.version, String(raw.createdAt ?? versions[0].createdAt), last.createdAt, modelId, externalUrl);
        for (const v of versions) {
          await t.versionInsert.run(raw.id, v.version, JSON.stringify(v.data), v.dataSha256, v.note, v.createdAt, `import:${actor}`);
        }
        await insertDocs(t, documents, raw.id, null);
        await appendAudit(t, {
          actor,
          action: 'passport.imported',
          target: raw.id,
          details: { versions: versions.length, documents: documents.length, source: String(bundle.source ?? '') },
        });
      });
      record('passport', id, 'imported', { versions: versions.length, documents: documents.length });
    } catch (err) {
      fail('passport', id, err);
    }
  }

  const count = (kind, status) => results.filter((r) => r.kind === kind && r.status === status).length;
  return {
    imported: count('passport', 'imported'),
    skipped: count('passport', 'skipped'),
    errors: count('passport', 'error'),
    models: { imported: count('model', 'imported'), skipped: count('model', 'skipped'), errors: count('model', 'error') },
    results,
  };
}
