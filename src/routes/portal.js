import { pipeline } from 'node:stream/promises';
import QRCode from 'qrcode';
import { appendAudit } from '../audit.js';
import { sha256 } from '../crypto.js';
import { tx } from '../db.js';
import { removeDocument, storeDocument } from '../documents.js';
import { HttpError, readForm, redirect, sendHtml } from '../http.js';
import {
  addModelVersion,
  addVersion,
  createModel,
  createPassportsBulk,
  effectiveData,
  ownModel,
  ownPassport,
  passportUrl,
} from '../passports.js';
import { buildExport } from '../portability.js';
import {
  checkOrigin,
  createPortalSession,
  hashPassword,
  MIN_PASSWORD,
  normalizeEmail,
  portalCookie,
  portalUser,
  PORTAL_SESSION_TTL_MS,
  verifyPassword,
} from '../portal/auth.js';
import { csvEscape, dataToForm, formToData, formValues, itemsFromCsv, readMultipart } from '../portal/forms.js';
import {
  dashboardPage,
  loginPage,
  messagePage,
  modelFormPage,
  modelPage,
  passportPage,
  setupPage,
} from '../portal/views.js';

const PAGE_SIZE = 100;
const FORM_LIMIT = 2 * 1024 * 1024;
const flashOf = (url) => url.searchParams.get('msg');
const noStore = { 'Cache-Control': 'private, no-store' };

/** Class used to leave a handler with a redirect to the login page. */
class LoginRequired extends Error {}

/**
 * Wraps a portal handler: resolves the logged-in user, checks the Origin of
 * POSTs, enforces "suspended = read only", and turns errors into pages.
 */
function page(handler, { write = false } = {}) {
  return async (ctx) => {
    const { req, res, st, config } = ctx;
    let user = null;
    try {
      if (req.method === 'POST') checkOrigin(req, config);
      user = await portalUser(req, st);
      if (!user) throw new LoginRequired();
      if (write && user.status !== 'active') {
        throw new HttpError(403, 'tenant_suspended', 'Contul este suspendat: modificările sunt blocate.');
      }
      return await handler({ ...ctx, user });
    } catch (err) {
      if (err instanceof LoginRequired) return redirect(res, '/portal/login');
      if (err instanceof HttpError && err.status < 500) {
        return sendHtml(req, res, err.status, messagePage({ title: 'Nu s-a putut finaliza', message: err.message, user }), noStore);
      }
      throw err;
    }
  };
}

const intOrUndefined = (v) => (v === null || v === undefined || v === '' ? undefined : Number.parseInt(v, 10));

export function registerPortalRoutes(router) {
  // ------------------------------------------------------------ auth

  router.get('/portal/login', async ({ req, res, url, st }) => {
    if (await portalUser(req, st)) return redirect(res, '/portal');
    sendHtml(req, res, 200, loginPage({ flash: flashOf(url) }), noStore);
  });

  router.post('/portal/login', async ({ req, res, st, config }) => {
    checkOrigin(req, config);
    const form = await readForm(req, 8192);
    const email = normalizeEmail(form.get('email'));
    const password = String(form.get('password') ?? '');
    const user = email ? await st.userByEmail.get(email) : null;
    const ok = await verifyPassword(password, user?.password_hash ?? null);
    if (!user || !ok) {
      return sendHtml(req, res, 401, loginPage({ error: 'E-mail sau parolă greșite.', email }), noStore);
    }
    const sid = await createPortalSession(st, user.id);
    redirect(res, '/portal', { 'Set-Cookie': portalCookie(config, sid, PORTAL_SESSION_TTL_MS / 1000) });
  });

  router.post('/portal/logout', async ({ req, res, st, config }) => {
    checkOrigin(req, config);
    const user = await portalUser(req, st);
    if (user) await st.portalSessionDelete.run(sha256(user.sid));
    redirect(res, '/portal/login', { 'Set-Cookie': portalCookie(config, '', 0) });
  });

  router.get('/portal/setup', async ({ req, res, url, st }) => {
    const token = url.searchParams.get('token') ?? '';
    const user = token ? await st.userBySetupToken.get(sha256(token), Date.now()) : null;
    if (!user) {
      return sendHtml(req, res, 404, messagePage({ title: 'Link expirat', message: 'Linkul de activare este invalid sau a expirat. Cereți un link nou administratorului.' }), noStore);
    }
    sendHtml(req, res, 200, setupPage({ token, email: user.email }), noStore);
  });

  router.post('/portal/setup', async ({ req, res, db, st, config }) => {
    checkOrigin(req, config);
    const form = await readForm(req, 8192);
    const token = String(form.get('token') ?? '');
    const user = token ? await st.userBySetupToken.get(sha256(token), Date.now()) : null;
    if (!user) {
      return sendHtml(req, res, 404, messagePage({ title: 'Link expirat', message: 'Linkul de activare este invalid sau a expirat.' }), noStore);
    }
    const password = String(form.get('password') ?? '');
    let error = null;
    if (password.length < MIN_PASSWORD) error = `Parola trebuie să aibă cel puțin ${MIN_PASSWORD} caractere.`;
    else if (password !== form.get('password2')) error = 'Parolele nu coincid.';
    if (error) return sendHtml(req, res, 400, setupPage({ token, email: user.email, error }), noStore);
    const hash = await hashPassword(password);
    await tx(db, async (t) => {
      await t.userSetPassword.run(hash, user.id);
      await t.portalSessionDeleteForUser.run(user.id);
      await appendAudit(t, { actor: `user:${user.id}`, action: 'user.password_set', target: user.id });
    });
    redirect(res, '/portal/login?msg=password_set');
  });

  // ------------------------------------------------------------ dashboard & models

  router.get('/portal', page(async ({ req, res, url, st, user }) => {
    const [models, recent, count] = await Promise.all([
      st.modelList.all(user.tenantId),
      st.passportRecent.all(user.tenantId, 10),
      st.passportCount.get(user.tenantId),
    ]);
    sendHtml(req, res, 200, dashboardPage({ user, models, recent, totalPassports: count.n, flash: flashOf(url) }), noStore);
  }));

  router.get('/portal/models/new', page(async ({ req, res, user }) => {
    sendHtml(req, res, 200, modelFormPage({ user, model: null, values: { category: 'industrial' } }), noStore);
  }, { write: true }));

  router.post('/portal/models', page(async ({ req, res, db, user }) => {
    const form = await readForm(req, FORM_LIMIT);
    const values = formValues(form);
    const { data, errors } = formToData(form, 'model');
    if (errors.length) return sendHtml(req, res, 400, modelFormPage({ user, model: null, values, errors }), noStore);
    try {
      const model = await createModel(db, { tenant: user, name: form.get('name'), category: form.get('category'), data, note: form.get('note') || undefined });
      redirect(res, `/portal/models/${encodeURIComponent(model.id)}?msg=model_created`);
    } catch (err) {
      if (err instanceof HttpError && err.status < 500) {
        return sendHtml(req, res, 400, modelFormPage({ user, model: null, values, errors: [err.message] }), noStore);
      }
      throw err;
    }
  }, { write: true }));

  async function renderModel(ctx, { status = 200, errors, bulkText } = {}) {
    const { req, res, url, st, params, user } = ctx;
    const model = await ownModel(st, user, params.id);
    const pageNo = Math.max(1, Number.parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
    const [v, docs, passports, count] = await Promise.all([
      st.modelVersionGet.get(model.id, model.current_version),
      st.modelDocActive.all(model.id),
      st.passportListByModel.all(model.id, PAGE_SIZE, (pageNo - 1) * PAGE_SIZE),
      st.passportCountByModel.get(model.id),
    ]);
    sendHtml(req, res, status, modelPage({
      user,
      model,
      data: JSON.parse(v.data),
      docs,
      passports,
      total: count.n,
      page: pageNo,
      pageSize: PAGE_SIZE,
      flash: flashOf(url),
      errors,
      bulkText,
    }), noStore);
  }

  router.get('/portal/models/:id', page((ctx) => renderModel(ctx)));

  router.get('/portal/models/:id/edit', page(async ({ req, res, st, params, user }) => {
    const model = await ownModel(st, user, params.id);
    const v = await st.modelVersionGet.get(model.id, model.current_version);
    sendHtml(req, res, 200, modelFormPage({ user, model, values: dataToForm(JSON.parse(v.data), 'model') }), noStore);
  }, { write: true }));

  router.post('/portal/models/:id', page(async ({ req, res, db, st, params, user, snapshots }) => {
    const model = await ownModel(st, user, params.id);
    const form = await readForm(req, FORM_LIMIT);
    const { data, errors } = formToData(form, 'model');
    if (errors.length) return sendHtml(req, res, 400, modelFormPage({ user, model, values: formValues(form), errors }), noStore);
    try {
      const result = await addModelVersion(db, {
        tenant: user,
        model,
        data,
        note: form.get('note') || undefined,
        expectedVersion: intOrUndefined(form.get('expectedVersion')),
      });
      if (result.changed) snapshots.invalidateAll();
      redirect(res, `/portal/models/${encodeURIComponent(model.id)}?msg=${result.changed ? 'model_updated' : 'model_unchanged'}`);
    } catch (err) {
      if (err instanceof HttpError && err.status === 409) {
        return sendHtml(req, res, 409, modelFormPage({ user, model, values: formValues(form), errors: ['Modelul a fost modificat între timp de altcineva. Reîncărcați pagina.'] }), noStore);
      }
      throw err;
    }
  }, { write: true }));

  router.post('/portal/models/:id/passports', page(async (ctx) => {
    const { req, res, db, st, params, user, config } = ctx;
    const model = await ownModel(st, user, params.id);
    const form = await readMultipart(req, config.maxDocumentBytes);
    const file = form.get('csv');
    const pasted = String(form.get('items') ?? '');
    const text = file && typeof file !== 'string' && file.size ? await file.text() : pasted;
    try {
      const items = itemsFromCsv(text);
      await createPassportsBulk(db, { tenant: user, model, items });
      redirect(res, `/portal/models/${encodeURIComponent(model.id)}?msg=passports_created`);
    } catch (err) {
      if (err instanceof HttpError && err.status < 500) {
        return renderModel(ctx, { status: err.status, errors: [err.message], bulkText: pasted });
      }
      throw err;
    }
  }, { write: true }));

  router.get('/portal/models/:id/passports.csv', page(async ({ req, res, st, params, user, config }) => {
    const model = await ownModel(st, user, params.id);
    const lines = ['productIdentifier,url'];
    for (let offset = 0; ; offset += 1000) {
      const rows = await st.passportListByModel.all(model.id, 1000, offset);
      for (const p of rows) lines.push(`${csvEscape(p.product_identifier)},${csvEscape(passportUrl(config, p.id))}`);
      if (rows.length < 1000) break;
    }
    const body = `﻿${lines.join('\r\n')}\r\n`;
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(`${model.name}-qr.csv`)}`,
      ...noStore,
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  }));

  // ------------------------------------------------------------ passports

  async function renderPassport(ctx, { status = 200, errors, values } = {}) {
    const { req, res, url, st, params, user, config } = ctx;
    const passport = await ownPassport(st, user, params.id);
    const model = passport.model_id ? await st.modelById.get(passport.model_id) : null;
    const [v, versions, docs, mv, modelDocs] = await Promise.all([
      st.versionGet.get(passport.id, passport.current_version),
      st.versionList.all(passport.id),
      st.docActive.all(passport.id),
      model ? st.modelVersionGet.get(model.id, model.current_version) : null,
      model ? st.modelDocActive.all(model.id) : [],
    ]);
    const itemData = JSON.parse(v.data);
    const publicUrl = passportUrl(config, passport.id);
    sendHtml(req, res, status, passportPage({
      user,
      passport,
      model,
      values: values ?? dataToForm(itemData, 'item'),
      effective: effectiveData(mv ? JSON.parse(mv.data) : null, itemData),
      docs: [...modelDocs, ...docs],
      versions,
      qrSvg: await QRCode.toString(publicUrl, { type: 'svg', errorCorrectionLevel: 'M', margin: 1 }),
      publicUrl,
      flash: flashOf(url),
      errors,
    }), noStore);
  }

  router.get('/portal/passports/:id', page((ctx) => renderPassport(ctx)));

  router.post('/portal/passports/:id', page(async (ctx) => {
    const { req, res, db, st, params, user, snapshots } = ctx;
    const passport = await ownPassport(st, user, params.id);
    const form = await readForm(req, FORM_LIMIT);
    const { data, errors } = formToData(form, 'item');
    if (errors.length) return renderPassport(ctx, { status: 400, errors, values: formValues(form) });
    try {
      await addVersion(db, { tenant: user, passport, data, note: form.get('note') || undefined, expectedVersion: intOrUndefined(form.get('expectedVersion')) });
    } catch (err) {
      if (err instanceof HttpError && err.status === 409) {
        return renderPassport(ctx, { status: 409, errors: ['Pașaportul a fost modificat între timp. Reîncărcați pagina.'], values: formValues(form) });
      }
      throw err;
    }
    snapshots.invalidate(passport.id);
    redirect(res, `/portal/passports/${encodeURIComponent(passport.id)}?msg=passport_updated`);
  }, { write: true }));

  router.get('/portal/passports/:id/qr.svg', page(async ({ req, res, st, params, user, config }) => {
    const passport = await ownPassport(st, user, params.id);
    // High error correction: labels on batteries get scratched.
    const svg = await QRCode.toString(passportUrl(config, passport.id), { type: 'svg', errorCorrectionLevel: 'Q', margin: 2 });
    res.writeHead(200, {
      'Content-Type': 'image/svg+xml',
      'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(`qr-${passport.product_identifier}.svg`)}`,
      'Content-Security-Policy': "default-src 'none'",
      ...noStore,
    });
    res.end(svg);
  }));

  // ------------------------------------------------------------ documents

  const upload = (kind) => page(async ({ req, res, db, st, blobs, params, user, config, snapshots }) => {
    const owner = kind === 'model' ? await ownModel(st, user, params.id) : await ownPassport(st, user, params.id);
    const form = await readMultipart(req, config.maxDocumentBytes);
    const file = form.get('file');
    if (!file || typeof file === 'string' || !file.size) throw new HttpError(400, 'invalid_request', 'Alegeți un fișier.');
    await storeDocument(db, blobs, {
      tenant: user,
      passportId: kind === 'passport' ? owner.id : null,
      modelId: kind === 'model' ? owner.id : null,
      name: file.name || 'document',
      access: String(form.get('access') ?? 'public'),
      contentType: file.type,
      buf: Buffer.from(await file.arrayBuffer()),
    });
    if (kind === 'model') snapshots.invalidateAll();
    else snapshots.invalidate(owner.id);
    redirect(res, `/portal/${kind}s/${encodeURIComponent(owner.id)}?msg=document_added`);
  }, { write: true });

  const remove = (kind) => page(async ({ res, db, st, params, user, snapshots }) => {
    const owner = kind === 'model' ? await ownModel(st, user, params.id) : await ownPassport(st, user, params.id);
    await removeDocument(db, {
      tenant: user,
      passportId: kind === 'passport' ? owner.id : null,
      modelId: kind === 'model' ? owner.id : null,
      documentId: params.docId,
    });
    if (kind === 'model') snapshots.invalidateAll();
    else snapshots.invalidate(owner.id);
    redirect(res, `/portal/${kind}s/${encodeURIComponent(owner.id)}?msg=document_removed`);
  }, { write: true });

  router.post('/portal/models/:id/documents', upload('model'));
  router.post('/portal/models/:id/documents/:docId/remove', remove('model'));
  router.post('/portal/passports/:id/documents', upload('passport'));
  router.post('/portal/passports/:id/documents/:docId/remove', remove('passport'));

  // The client can always open its own documents, whatever their access level.
  router.get('/portal/documents/:docId', page(async ({ req, res, st, blobs, params, user }) => {
    const doc = await st.docForTenant.get(params.docId, user.tenantId);
    if (!doc) throw new HttpError(404, 'document_not_found', 'Documentul nu a fost găsit.');
    const stream = await blobs.open(doc.sha256);
    res.writeHead(200, {
      'Content-Type': doc.content_type,
      'Content-Length': doc.size,
      'Content-Disposition': `${doc.content_type === 'application/pdf' || doc.content_type.startsWith('image/') ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(doc.name)}`,
      'Content-Security-Policy': doc.content_type === 'application/pdf' ? "default-src 'none'; frame-ancestors 'none'" : "sandbox; default-src 'none'",
      ...noStore,
    });
    await pipeline(stream, res);
  }));

  // ------------------------------------------------------------ export

  router.get('/portal/export', page(async ({ req, res, db, st, blobs, user, config }) => {
    const bundle = await buildExport(st, blobs, config, user, { includeDocuments: true });
    await tx(db, (t) => appendAudit(t, { actor: user.actor, action: 'tenant.exported', target: user.tenantId, details: { via: 'portal' } }));
    const body = JSON.stringify(bundle);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="dpp-export-${new Date().toISOString().slice(0, 10)}.json"`,
      ...noStore,
    });
    res.end(body);
  }));
}
