import { randomBytes, randomUUID } from 'node:crypto';
import { ACCESSOR_TOKEN_PREFIX, requireAdmin, TENANT_KEY_PREFIX } from '../auth.js';
import { appendAudit, verifyAudit } from '../audit.js';
import { newToken, sha256 } from '../crypto.js';
import { isUniqueViolation, tx } from '../db.js';
import { isEmail, normalizeEmail, SETUP_TTL_MS } from '../portal/auth.js';
import { badRequest, clampInt, HttpError, readJson, sendJson } from '../http.js';

const str = (v, field, max = 200, optional = false) => {
  if (optional && (v === undefined || v === null)) return null;
  if (typeof v !== 'string' || !v.trim() || v.length > max) throw badRequest(`${field} must be a non-empty string (max ${max})`);
  return v.trim();
};

/**
 * Platform operator API. Creating an accessor is where organisations with
 * restricted access (authorities, recyclers, repairers...) are onboarded, after
 * their identity and legitimate interest have been verified out of band.
 */
export function registerAdminRoutes(router) {
  const withAdmin = (handler) => async (ctx) => {
    requireAdmin(ctx.req, ctx.config);
    return handler(ctx);
  };

  router.post('/admin/tenants', withAdmin(async ({ req, res, db, config }) => {
    const body = await readJson(req, config.maxJsonBytes);
    const name = str(body.name, 'name');
    const vatId = str(body.vatId, 'vatId', 50, true);
    const id = randomUUID();
    const keyId = randomUUID();
    const apiKey = newToken(TENANT_KEY_PREFIX);
    const now = new Date().toISOString();
    const tenant = await tx(db, async (t) => {
      await t.tenantInsert.run(id, name, vatId, now);
      await t.apiKeyInsert.run(keyId, id, sha256(apiKey), now);
      await appendAudit(t, { actor: 'admin', action: 'tenant.created', target: id, details: { name, apiKeyId: keyId } });
      return t.tenantById.get(id);
    });
    sendJson(req, res, 201, { tenant, apiKey: { id: keyId, token: apiKey } });
  }));

  router.get('/admin/tenants', withAdmin(async ({ req, res, st }) => sendJson(req, res, 200, { items: await st.tenantList.all() })));

  router.post('/admin/tenants/:id/api-keys', withAdmin(async ({ req, res, params, db, st }) => {
    if (!(await st.tenantById.get(params.id))) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
    const keyId = randomUUID();
    const apiKey = newToken(TENANT_KEY_PREFIX);
    await tx(db, async (t) => {
      await t.apiKeyInsert.run(keyId, params.id, sha256(apiKey), new Date().toISOString());
      await appendAudit(t, { actor: 'admin', action: 'apikey.created', target: params.id, details: { apiKeyId: keyId } });
    });
    sendJson(req, res, 201, { id: keyId, token: apiKey });
  }));

  router.post('/admin/api-keys/:id/revoke', withAdmin(async ({ req, res, params, db }) => {
    const ok = await tx(db, async (t) => {
      if (!(await t.apiKeyRevoke.run(new Date().toISOString(), params.id)).changes) return false;
      await appendAudit(t, { actor: 'admin', action: 'apikey.revoked', target: params.id });
      return true;
    });
    if (!ok) throw new HttpError(404, 'api_key_not_found', 'API key not found or already revoked');
    sendJson(req, res, 200, { revoked: true });
  }));

  // Suspension blocks changes only. Existing passports stay publicly reachable:
  // availability must not depend on the client's subscription being paid.
  for (const [action, status] of [['suspend', 'suspended'], ['reactivate', 'active']]) {
    router.post(`/admin/tenants/:id/${action}`, withAdmin(async ({ req, res, params, db }) => {
      const tenant = await tx(db, async (t) => {
        if (!(await t.tenantSetStatus.run(status, params.id)).changes) return null;
        await appendAudit(t, { actor: 'admin', action: `tenant.${action}`, target: params.id });
        return t.tenantById.get(params.id);
      });
      if (!tenant) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
      sendJson(req, res, 200, tenant);
    }));
  }

  // Portal users: the admin creates the account, the person sets their own
  // password through a one-time link (valid 7 days). No password is ever sent.
  const setupLink = (config, token) => `${config.baseUrl}/portal/setup?token=${encodeURIComponent(token)}`;

  router.post('/admin/tenants/:id/users', withAdmin(async ({ req, res, params, db, st, config }) => {
    if (!(await st.tenantById.get(params.id))) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
    const body = await readJson(req, config.maxJsonBytes);
    const email = normalizeEmail(body.email);
    if (!isEmail(email)) throw badRequest('email is not valid');
    const id = randomUUID();
    const token = randomBytes(32).toString('base64url');
    try {
      await tx(db, async (t) => {
        await t.userInsert.run(id, params.id, email, sha256(token), Date.now() + SETUP_TTL_MS, new Date().toISOString());
        await appendAudit(t, { actor: 'admin', action: 'user.created', target: id, details: { tenantId: params.id } });
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw new HttpError(409, 'conflict', 'A user with this email already exists');
      throw err;
    }
    sendJson(req, res, 201, { user: { id, email, tenantId: params.id }, setupUrl: setupLink(config, token), expiresInDays: 7 });
  }));

  router.get('/admin/tenants/:id/users', withAdmin(async ({ req, res, params, st }) => {
    sendJson(req, res, 200, { items: await st.userList.all(params.id) });
  }));

  // New one-time link, e.g. forgotten password. Existing sessions are closed.
  router.post('/admin/users/:id/reset', withAdmin(async ({ req, res, params, db, st, config }) => {
    if (!(await st.userById.get(params.id))) throw new HttpError(404, 'user_not_found', 'User not found');
    const token = randomBytes(32).toString('base64url');
    await tx(db, async (t) => {
      await t.userResetSetup.run(sha256(token), Date.now() + SETUP_TTL_MS, params.id);
      await t.portalSessionDeleteForUser.run(params.id);
      await appendAudit(t, { actor: 'admin', action: 'user.reset', target: params.id });
    });
    sendJson(req, res, 200, { setupUrl: setupLink(config, token), expiresInDays: 7 });
  }));

  router.post('/admin/accessors', withAdmin(async ({ req, res, db, config }) => {
    const body = await readJson(req, config.maxJsonBytes);
    const name = str(body.name, 'name');
    if (!['legitimate_interest', 'authority'].includes(body.role)) {
      throw badRequest('role must be legitimate_interest or authority');
    }
    const id = randomUUID();
    const token = newToken(ACCESSOR_TOKEN_PREFIX);
    await tx(db, async (t) => {
      await t.accessorInsert.run(id, name, body.role, sha256(token), new Date().toISOString());
      await appendAudit(t, { actor: 'admin', action: 'accessor.created', target: id, details: { name, role: body.role } });
    });
    sendJson(req, res, 201, { accessor: { id, name, role: body.role }, token });
  }));

  router.get('/admin/accessors', withAdmin(async ({ req, res, st }) => sendJson(req, res, 200, { items: await st.accessorList.all() })));

  router.post('/admin/accessors/:id/revoke', withAdmin(async ({ req, res, params, db }) => {
    const ok = await tx(db, async (t) => {
      if (!(await t.accessorRevoke.run(new Date().toISOString(), params.id)).changes) return false;
      await t.sessionDeleteForAccessor.run(params.id);
      await appendAudit(t, { actor: 'admin', action: 'accessor.revoked', target: params.id });
      return true;
    });
    if (!ok) throw new HttpError(404, 'accessor_not_found', 'Accessor not found or already revoked');
    sendJson(req, res, 200, { revoked: true });
  }));

  router.get('/admin/audit', withAdmin(async ({ req, res, url, st }) => {
    const limit = clampInt(url.searchParams.get('limit'), 1, 1000, 100);
    sendJson(req, res, 200, { items: await st.auditRecent.all(limit) });
  }));

  router.get('/admin/audit/verify', withAdmin(async ({ req, res, st }) => sendJson(req, res, 200, await verifyAudit(st))));
}
