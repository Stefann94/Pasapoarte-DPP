import { randomUUID } from 'node:crypto';
import { requireTenant } from '../auth.js';
import { appendAudit } from '../audit.js';
import { tx } from '../db.js';
import { badRequest, clampInt, HttpError, readBody, readJson, sendJson } from '../http.js';
import {
  addVersion,
  createPassport,
  documentJson,
  DOCUMENT_TYPES,
  ownPassport,
  passportUrl,
  validateAccess,
  validateDocumentName,
} from '../passports.js';
import { buildExport, importBundle } from '../portability.js';

const summary = (config, p) => ({
  id: p.id,
  url: passportUrl(config, p.id),
  productIdentifier: p.product_identifier,
  category: p.category,
  currentVersion: p.current_version,
  createdAt: p.created_at,
  updatedAt: p.updated_at,
});

/** API for economic operators (or the platforms that generate their passports). */
export function registerTenantRoutes(router) {
  router.post('/api/passports', async ({ req, res, db, st, config }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const body = await readJson(req, config.maxJsonBytes);
    const created = await createPassport(db, {
      tenant,
      id: body.id,
      productIdentifier: body.productIdentifier,
      category: body.category,
      data: body.data,
      note: body.note,
    });
    sendJson(req, res, 201, { ...created, url: passportUrl(config, created.id) });
  });

  router.get('/api/passports', async ({ req, res, url, st, config }) => {
    const tenant = await requireTenant(req, st);
    const limit = clampInt(url.searchParams.get('limit'), 1, 500, 100);
    const offset = clampInt(url.searchParams.get('offset'), 0, 2_000_000_000, 0);
    const [rows, count] = await Promise.all([
      st.passportList.all(tenant.tenantId, limit, offset),
      st.passportCount.get(tenant.tenantId),
    ]);
    sendJson(req, res, 200, { total: count.n, limit, offset, items: rows.map((p) => summary(config, p)) });
  });

  router.get('/api/passports/:id', async ({ req, res, params, st, config }) => {
    const tenant = await requireTenant(req, st);
    const p = await ownPassport(st, tenant, params.id);
    const [v, versions, docs] = await Promise.all([
      st.versionGet.get(p.id, p.current_version),
      st.versionList.all(p.id),
      st.docActive.all(p.id),
    ]);
    sendJson(req, res, 200, {
      ...summary(config, p),
      dataSha256: v.data_hash,
      data: JSON.parse(v.data),
      versions: versions.map((x) => ({
        version: x.version,
        dataSha256: x.data_hash,
        note: x.note,
        createdAt: x.created_at,
        createdBy: x.created_by,
      })),
      documents: docs.map((d) => documentJson(config, p.id, d)),
    });
  });

  router.put('/api/passports/:id', async ({ req, res, params, db, st, config, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const passport = await ownPassport(st, tenant, params.id);
    const body = await readJson(req, config.maxJsonBytes);
    if (body.expectedVersion !== undefined && !Number.isInteger(body.expectedVersion)) {
      throw badRequest('expectedVersion must be an integer');
    }
    const result = await addVersion(db, {
      tenant,
      passport,
      data: body.data,
      note: body.note,
      expectedVersion: body.expectedVersion,
    });
    snapshots.invalidate(passport.id);
    sendJson(req, res, 200, { ...result, url: passportUrl(config, passport.id) });
  });

  router.get('/api/passports/:id/versions/:version', async ({ req, res, params, st }) => {
    const tenant = await requireTenant(req, st);
    const p = await ownPassport(st, tenant, params.id);
    const n = Number(params.version);
    const v = Number.isInteger(n) && n > 0 && n < 2 ** 31 ? await st.versionGet.get(p.id, n) : null;
    if (!v) throw new HttpError(404, 'version_not_found', 'Version not found');
    sendJson(req, res, 200, {
      id: p.id,
      version: v.version,
      dataSha256: v.data_hash,
      note: v.note,
      createdAt: v.created_at,
      createdBy: v.created_by,
      data: JSON.parse(v.data),
    });
  });

  // Raw upload: POST body is the file, Content-Type its media type,
  // ?name=...&access=public|legitimate_interest|authority
  router.post('/api/passports/:id/documents', async ({ req, res, url, params, db, st, blobs, config, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const passport = await ownPassport(st, tenant, params.id);
    const name = validateDocumentName(url.searchParams.get('name') ?? '');
    const access = validateAccess(url.searchParams.get('access') ?? 'public');
    const contentType = (req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    const sniff = DOCUMENT_TYPES[contentType];
    if (!sniff) {
      throw new HttpError(415, 'unsupported_media_type', `Allowed types: ${Object.keys(DOCUMENT_TYPES).join(', ')}`);
    }
    const buf = await readBody(req, config.maxDocumentBytes);
    if (!buf.length) throw badRequest('Document is empty');
    if (!sniff(buf)) throw badRequest(`File content does not match Content-Type ${contentType}`);

    const hash = await blobs.put(buf);
    const id = randomUUID();
    const now = new Date().toISOString();
    const actor = `key:${tenant.keyId}`;
    const doc = await tx(db, async (t) => {
      await t.docInsert.run(id, passport.id, name, contentType, buf.length, hash, access, now, null);
      await t.passportTouch.run(now, passport.id);
      await appendAudit(t, { actor, action: 'document.added', target: passport.id, details: { documentId: id, sha256: hash, access } });
      return t.docGet.get(id, passport.id);
    });
    snapshots.invalidate(passport.id);
    sendJson(req, res, 201, documentJson(config, passport.id, doc));
  });

  router.delete('/api/passports/:id/documents/:docId', async ({ req, res, params, db, st, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const passport = await ownPassport(st, tenant, params.id);
    const now = new Date().toISOString();
    const actor = `key:${tenant.keyId}`;
    const removed = await tx(db, async (t) => {
      const r = await t.docRemove.run(now, params.docId, passport.id);
      if (!r.changes) return false;
      await t.passportTouch.run(now, passport.id);
      await appendAudit(t, { actor, action: 'document.removed', target: passport.id, details: { documentId: params.docId } });
      return true;
    });
    if (!removed) throw new HttpError(404, 'document_not_found', 'Document not found');
    snapshots.invalidate(passport.id);
    // The file itself is kept: removal hides it but the history stays auditable.
    sendJson(req, res, 200, { removed: true });
  });

  // Full export: every passport, every version and (by default) every document.
  // Allowed even when the account is suspended, so a client can always leave.
  router.get('/api/export', async ({ req, res, url, db, st, blobs, config }) => {
    const tenant = await requireTenant(req, st);
    const includeDocuments = url.searchParams.get('includeDocuments') !== '0';
    const bundle = await buildExport(st, blobs, config, tenant, { includeDocuments });
    await tx(db, (t) =>
      appendAudit(t, {
        actor: `key:${tenant.keyId}`,
        action: 'tenant.exported',
        target: tenant.tenantId,
        details: { passports: bundle.passports.length, includeDocuments },
      }),
    );
    sendJson(req, res, 200, bundle, {
      'Content-Disposition': `attachment; filename="dpp-export-${new Date().toISOString().slice(0, 10)}.json"`,
    });
  });

  // Import a bundle produced by /api/export (here or on another host using the same format).
  router.post('/api/import', async ({ req, res, db, st, blobs, config }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const bundle = await readJson(req, config.maxImportBytes);
    sendJson(req, res, 200, await importBundle(db, st, blobs, tenant, bundle));
  });
}
