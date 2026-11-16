import { requireTenant } from '../auth.js';
import { appendAudit } from '../audit.js';
import { tx } from '../db.js';
import { removeDocument, storeDocument } from '../documents.js';
import { badRequest, clampInt, HttpError, readBody, readJson, sendJson } from '../http.js';
import {
  addModelVersion,
  addVersion,
  createModel,
  createPassport,
  createPassportsBulk,
  documentJson,
  effectiveData,
  ownModel,
  ownPassport,
  passportUrl,
} from '../passports.js';
import { buildExport, importBundle } from '../portability.js';
import { checkMirror, mirrorEventJson, mirrorJson, runDueChecks, validateExternalUrl } from '../mirror.js';
import { safeEqual } from '../crypto.js';
import { bearer } from '../auth.js';

const summary = (config, p) => ({
  id: p.id,
  url: passportUrl(config, p.id),
  productIdentifier: p.product_identifier,
  category: p.category,
  modelId: p.model_id ?? null,
  externalUrl: p.external_url ?? null,
  mirrorStatus: p.external_url ? (p.mirror_status ?? 'unchecked') : null,
  currentVersion: p.current_version,
  createdAt: p.created_at,
  updatedAt: p.updated_at,
});

const modelSummary = (m) => ({
  id: m.id,
  name: m.name,
  category: m.category,
  currentVersion: m.current_version,
  passportCount: m.passport_count,
  createdAt: m.created_at,
  updatedAt: m.updated_at,
});

const expectedVersionOf = (body) => {
  if (body.expectedVersion !== undefined && !Number.isInteger(body.expectedVersion)) {
    throw badRequest('expectedVersion must be an integer');
  }
  return body.expectedVersion;
};

/** API for economic operators (or the platforms that generate their passports). */
export function registerTenantRoutes(router) {
  // ------------------------------------------------------------ models

  router.post('/api/models', async ({ req, res, db, st, config }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const body = await readJson(req, config.maxJsonBytes);
    sendJson(req, res, 201, await createModel(db, { tenant, name: body.name, category: body.category, data: body.data, note: body.note }));
  });

  router.get('/api/models', async ({ req, res, st }) => {
    const tenant = await requireTenant(req, st);
    sendJson(req, res, 200, { items: (await st.modelList.all(tenant.tenantId)).map(modelSummary) });
  });

  router.get('/api/models/:id', async ({ req, res, params, st, config }) => {
    const tenant = await requireTenant(req, st);
    const m = await ownModel(st, tenant, params.id);
    const [v, versions, docs, count] = await Promise.all([
      st.modelVersionGet.get(m.id, m.current_version),
      st.modelVersionAll.all(m.id),
      st.modelDocActive.all(m.id),
      st.passportCountByModel.get(m.id),
    ]);
    sendJson(req, res, 200, {
      ...modelSummary({ ...m, passport_count: count.n }),
      dataSha256: v.data_hash,
      data: JSON.parse(v.data),
      versions: versions.map((x) => ({ version: x.version, dataSha256: x.data_hash, note: x.note, createdAt: x.created_at, createdBy: x.created_by })),
      documents: docs.map((d) => documentJson(config, null, d)),
    });
  });

  router.put('/api/models/:id', async ({ req, res, params, db, st, config, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const model = await ownModel(st, tenant, params.id);
    const body = await readJson(req, config.maxJsonBytes);
    const result = await addModelVersion(db, { tenant, model, data: body.data, note: body.note, expectedVersion: expectedVersionOf(body) });
    if (result.changed) snapshots.invalidateAll();
    sendJson(req, res, 200, result);
  });

  // Many batteries of one model at once: {items: [{productIdentifier, id?, data?}], note?}
  router.post('/api/models/:id/passports', async ({ req, res, params, db, st, config }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const model = await ownModel(st, tenant, params.id);
    const body = await readJson(req, config.maxImportBytes);
    const created = await createPassportsBulk(db, {
      tenant,
      model,
      items: body.items,
      note: body.note,
      urlOptions: { allowInsecure: config.mirrorAllowPrivate },
    });
    sendJson(req, res, 201, { created: created.length, items: created.map((c) => ({ ...c, url: passportUrl(config, c.id) })) });
  });

  router.get('/api/models/:id/passports', async ({ req, res, url, params, st, config }) => {
    const tenant = await requireTenant(req, st);
    const model = await ownModel(st, tenant, params.id);
    const limit = clampInt(url.searchParams.get('limit'), 1, 1000, 100);
    const offset = clampInt(url.searchParams.get('offset'), 0, 2_000_000_000, 0);
    const [rows, count] = await Promise.all([st.passportListByModel.all(model.id, limit, offset), st.passportCountByModel.get(model.id)]);
    sendJson(req, res, 200, { total: count.n, limit, offset, items: rows.map((p) => summary(config, p)) });
  });

  router.post('/api/models/:id/documents', async ({ req, res, url, params, db, st, blobs, config, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const model = await ownModel(st, tenant, params.id);
    const buf = await readBody(req, config.maxDocumentBytes);
    const doc = await storeDocument(db, blobs, {
      tenant,
      modelId: model.id,
      name: url.searchParams.get('name') ?? '',
      access: url.searchParams.get('access') ?? 'public',
      contentType: req.headers['content-type'],
      buf,
    });
    snapshots.invalidateAll();
    sendJson(req, res, 201, documentJson(config, null, doc));
  });

  router.delete('/api/models/:id/documents/:docId', async ({ req, res, params, db, st, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const model = await ownModel(st, tenant, params.id);
    await removeDocument(db, { tenant, modelId: model.id, documentId: params.docId });
    snapshots.invalidateAll();
    sendJson(req, res, 200, { removed: true });
  });

  // ------------------------------------------------------------ passports

  router.post('/api/passports', async ({ req, res, db, st, blobs, config }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const body = await readJson(req, config.maxJsonBytes);
    const created = await createPassport(db, {
      tenant,
      id: body.id,
      productIdentifier: body.productIdentifier,
      category: body.category,
      modelId: body.modelId,
      data: body.data,
      note: body.note,
      externalUrl: body.externalUrl,
      urlOptions: { allowInsecure: config.mirrorAllowPrivate },
    });
    let mirror = null;
    if (created.externalUrl) {
      // First EU copy right away, so continuity starts on day one.
      mirror = await checkMirror(st, blobs, config, await st.passportById.get(created.id));
    }
    sendJson(req, res, 201, { ...created, url: passportUrl(config, created.id), mirror });
  });

  // Set, change or remove (null) the external host of a passport.
  router.put('/api/passports/:id/external', async ({ req, res, params, db, st, blobs, config, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const passport = await ownPassport(st, tenant, params.id);
    const body = await readJson(req, config.maxJsonBytes);
    const ext = body.externalUrl ? validateExternalUrl(body.externalUrl, { allowInsecure: config.mirrorAllowPrivate }) : null;
    await tx(db, async (t) => {
      await t.passportSetExternal.run(ext, new Date().toISOString(), passport.id);
      await appendAudit(t, { actor: tenant.actor, action: 'passport.external_set', target: passport.id, details: { externalUrl: ext } });
    });
    const mirror = ext ? await checkMirror(st, blobs, config, await st.passportById.get(passport.id)) : null;
    snapshots.invalidate(passport.id);
    sendJson(req, res, 200, { id: passport.id, externalUrl: ext, mirror });
  });

  router.post('/api/passports/:id/mirror/check', async ({ req, res, params, st, blobs, config, snapshots }) => {
    const tenant = await requireTenant(req, st);
    const passport = await ownPassport(st, tenant, params.id);
    if (!passport.external_url) throw badRequest('This passport is hosted here, not externally');
    const result = await checkMirror(st, blobs, config, passport);
    snapshots.invalidate(passport.id);
    sendJson(req, res, 200, { ...result, mirror: mirrorJson(await st.passportById.get(passport.id)) });
  });

  router.get('/api/passports/:id/mirror', async ({ req, res, params, st }) => {
    const tenant = await requireTenant(req, st);
    const passport = await ownPassport(st, tenant, params.id);
    if (!passport.external_url) throw badRequest('This passport is hosted here, not externally');
    sendJson(req, res, 200, { ...mirrorJson(passport), events: (await st.mirrorEvents.all(passport.id)).map(mirrorEventJson) });
  });

  // Daily job (Vercel Cron). With CRON_SECRET set, Vercel sends it as a bearer
  // token. Without it the endpoint still only checks passports not checked for
  // 12 hours, so calling it repeatedly cannot cause extra outbound traffic.
  router.get('/api/cron/mirror', async ({ req, res, st, blobs, config, snapshots }) => {
    if (config.cronSecret) {
      const token = bearer(req);
      if (!token || !(safeEqual(token, config.cronSecret) || safeEqual(token, config.adminToken))) {
        throw new HttpError(401, 'unauthorized', 'Missing or invalid credentials');
      }
    }
    const summary = await runDueChecks(st, blobs, config, { limit: 300 });
    if (summary.checked) snapshots.invalidateAll();
    sendJson(req, res, 200, summary);
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
    const model = p.model_id ? await st.modelById.get(p.model_id) : null;
    const [v, versions, docs, mv, modelDocs] = await Promise.all([
      st.versionGet.get(p.id, p.current_version),
      st.versionList.all(p.id),
      st.docActive.all(p.id),
      model ? st.modelVersionGet.get(model.id, model.current_version) : null,
      model ? st.modelDocActive.all(model.id) : [],
    ]);
    const itemData = JSON.parse(v.data);
    sendJson(req, res, 200, {
      ...summary(config, p),
      model: model ? { id: model.id, name: model.name, version: model.current_version } : null,
      dataSha256: v.data_hash,
      data: itemData,
      effectiveData: effectiveData(mv ? JSON.parse(mv.data) : null, itemData),
      versions: versions.map((x) => ({
        version: x.version,
        dataSha256: x.data_hash,
        note: x.note,
        createdAt: x.created_at,
        createdBy: x.created_by,
      })),
      documents: [...modelDocs, ...docs].map((d) => documentJson(config, p.id, d)),
      mirror: p.external_url ? mirrorJson(p) : null,
    });
  });

  router.put('/api/passports/:id', async ({ req, res, params, db, st, config, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const passport = await ownPassport(st, tenant, params.id);
    const body = await readJson(req, config.maxJsonBytes);
    const result = await addVersion(db, { tenant, passport, data: body.data, note: body.note, expectedVersion: expectedVersionOf(body) });
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
    const buf = await readBody(req, config.maxDocumentBytes);
    const doc = await storeDocument(db, blobs, {
      tenant,
      passportId: passport.id,
      name: url.searchParams.get('name') ?? '',
      access: url.searchParams.get('access') ?? 'public',
      contentType: req.headers['content-type'],
      buf,
    });
    snapshots.invalidate(passport.id);
    sendJson(req, res, 201, documentJson(config, passport.id, doc));
  });

  router.delete('/api/passports/:id/documents/:docId', async ({ req, res, params, db, st, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const passport = await ownPassport(st, tenant, params.id);
    await removeDocument(db, { tenant, passportId: passport.id, documentId: params.docId });
    snapshots.invalidate(passport.id);
    sendJson(req, res, 200, { removed: true });
  });

  // ------------------------------------------------------------ portability

  // Full export: models, passports, every version and (by default) every document.
  // Allowed even when the account is suspended, so a client can always leave.
  router.get('/api/export', async ({ req, res, url, db, st, blobs, config }) => {
    const tenant = await requireTenant(req, st);
    const includeDocuments = url.searchParams.get('includeDocuments') !== '0';
    const bundle = await buildExport(st, blobs, config, tenant, { includeDocuments });
    await tx(db, (t) =>
      appendAudit(t, {
        actor: tenant.actor,
        action: 'tenant.exported',
        target: tenant.tenantId,
        details: { models: bundle.models.length, passports: bundle.passports.length, includeDocuments },
      }),
    );
    sendJson(req, res, 200, bundle, {
      'Content-Disposition': `attachment; filename="dpp-export-${new Date().toISOString().slice(0, 10)}.json"`,
    });
  });

  // Import a bundle produced by /api/export (here or on another host using the same format).
  router.post('/api/import', async ({ req, res, db, st, blobs, config, snapshots }) => {
    const tenant = await requireTenant(req, st, { write: true });
    const bundle = await readJson(req, config.maxImportBytes);
    const result = await importBundle(db, st, blobs, tenant, bundle);
    snapshots.invalidateAll();
    sendJson(req, res, 200, result);
  });
}
