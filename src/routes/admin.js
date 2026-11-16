import { randomUUID } from 'node:crypto';
import { ACCESSOR_TOKEN_PREFIX, requireAdmin, TENANT_KEY_PREFIX } from '../auth.js';
import { appendAudit, verifyAudit } from '../audit.js';
import { newToken, sha256 } from '../crypto.js';
import { tx } from '../db.js';
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

  router.post('/admin/tenants', withAdmin(async ({ req, res, db, st, config }) => {
    const body = await readJson(req, config.maxJsonBytes);
    const name = str(body.name, 'name');
    const vatId = str(body.vatId, 'vatId', 50, true);
    const id = randomUUID();
    const keyId = randomUUID();
    const apiKey = newToken(TENANT_KEY_PREFIX);
    const now = new Date().toISOString();
    tx(db, () => {
      st.tenantInsert.run(id, name, vatId, now);
      st.apiKeyInsert.run(keyId, id, sha256(apiKey), now);
      appendAudit(st, { actor: 'admin', action: 'tenant.created', target: id, details: { name, apiKeyId: keyId } });
    });
    sendJson(req, res, 201, { tenant: st.tenantById.get(id), apiKey: { id: keyId, token: apiKey } });
  }));

  router.get('/admin/tenants', withAdmin(({ req, res, st }) => sendJson(req, res, 200, { items: st.tenantList.all() })));

  router.post('/admin/tenants/:id/api-keys', withAdmin(({ req, res, params, db, st }) => {
    if (!st.tenantById.get(params.id)) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
    const keyId = randomUUID();
    const apiKey = newToken(TENANT_KEY_PREFIX);
    tx(db, () => {
      st.apiKeyInsert.run(keyId, params.id, sha256(apiKey), new Date().toISOString());
      appendAudit(st, { actor: 'admin', action: 'apikey.created', target: params.id, details: { apiKeyId: keyId } });
    });
    sendJson(req, res, 201, { id: keyId, token: apiKey });
  }));

  router.post('/admin/api-keys/:id/revoke', withAdmin(({ req, res, params, db, st }) => {
    const ok = tx(db, () => {
      if (!st.apiKeyRevoke.run(new Date().toISOString(), params.id).changes) return false;
      appendAudit(st, { actor: 'admin', action: 'apikey.revoked', target: params.id });
      return true;
    });
    if (!ok) throw new HttpError(404, 'api_key_not_found', 'API key not found or already revoked');
    sendJson(req, res, 200, { revoked: true });
  }));

  // Suspension blocks changes only. Existing passports stay publicly reachable:
  // availability must not depend on the client's subscription being paid.
  for (const [action, status] of [['suspend', 'suspended'], ['reactivate', 'active']]) {
    router.post(`/admin/tenants/:id/${action}`, withAdmin(({ req, res, params, db, st }) => {
      const ok = tx(db, () => {
        if (!st.tenantSetStatus.run(status, params.id).changes) return false;
        appendAudit(st, { actor: 'admin', action: `tenant.${action}`, target: params.id });
        return true;
      });
      if (!ok) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
      sendJson(req, res, 200, st.tenantById.get(params.id));
    }));
  }

  router.post('/admin/accessors', withAdmin(async ({ req, res, db, st, config }) => {
    const body = await readJson(req, config.maxJsonBytes);
    const name = str(body.name, 'name');
    if (!['legitimate_interest', 'authority'].includes(body.role)) {
      throw badRequest('role must be legitimate_interest or authority');
    }
    const id = randomUUID();
    const token = newToken(ACCESSOR_TOKEN_PREFIX);
    tx(db, () => {
      st.accessorInsert.run(id, name, body.role, sha256(token), new Date().toISOString());
      appendAudit(st, { actor: 'admin', action: 'accessor.created', target: id, details: { name, role: body.role } });
    });
    sendJson(req, res, 201, { accessor: { id, name, role: body.role }, token });
  }));

  router.get('/admin/accessors', withAdmin(({ req, res, st }) => sendJson(req, res, 200, { items: st.accessorList.all() })));

  router.post('/admin/accessors/:id/revoke', withAdmin(({ req, res, params, db, st }) => {
    const ok = tx(db, () => {
      if (!st.accessorRevoke.run(new Date().toISOString(), params.id).changes) return false;
      st.sessionDeleteForAccessor.run(params.id);
      appendAudit(st, { actor: 'admin', action: 'accessor.revoked', target: params.id });
      return true;
    });
    if (!ok) throw new HttpError(404, 'accessor_not_found', 'Accessor not found or already revoked');
    sendJson(req, res, 200, { revoked: true });
  }));

  router.get('/admin/audit', withAdmin(({ req, res, url, st }) => {
    const limit = clampInt(url.searchParams.get('limit'), 1, 1000, 100);
    sendJson(req, res, 200, { items: st.auditRecent.all(limit) });
  }));

  router.get('/admin/audit/verify', withAdmin(({ req, res, st }) => sendJson(req, res, 200, verifyAudit(st))));
}
