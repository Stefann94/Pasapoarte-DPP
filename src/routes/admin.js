import { requireAdmin } from '../auth.js';
import { verifyAudit } from '../audit.js';
import { clampInt, readJson, sendJson } from '../http.js';
import {
  createAccessor,
  createApiKey,
  createTenant,
  createUser,
  resetUser,
  revokeAccessor,
  revokeApiKey,
  setTenantStatus,
} from '../admin-ops.js';

/** Platform operator JSON API (bearer ADMIN_TOKEN). The web console is in routes/console.js. */
export function registerAdminRoutes(router) {
  const withAdmin = (handler) => async (ctx) => {
    requireAdmin(ctx.req, ctx.config);
    return handler(ctx);
  };

  router.post('/admin/tenants', withAdmin(async ({ req, res, db, config }) => {
    const body = await readJson(req, config.maxJsonBytes);
    sendJson(req, res, 201, await createTenant(db, { name: body.name, vatId: body.vatId }));
  }));

  router.get('/admin/tenants', withAdmin(async ({ req, res, st }) => sendJson(req, res, 200, { items: await st.tenantList.all() })));

  router.post('/admin/tenants/:id/api-keys', withAdmin(async ({ req, res, params, db, st }) => {
    sendJson(req, res, 201, await createApiKey(db, st, params.id));
  }));

  router.post('/admin/api-keys/:id/revoke', withAdmin(async ({ req, res, params, db }) => {
    await revokeApiKey(db, params.id);
    sendJson(req, res, 200, { revoked: true });
  }));

  for (const action of ['suspend', 'reactivate']) {
    router.post(`/admin/tenants/:id/${action}`, withAdmin(async ({ req, res, params, db }) => {
      sendJson(req, res, 200, await setTenantStatus(db, params.id, action));
    }));
  }

  router.post('/admin/tenants/:id/users', withAdmin(async ({ req, res, params, db, st, config }) => {
    const body = await readJson(req, config.maxJsonBytes);
    sendJson(req, res, 201, await createUser(db, st, config, params.id, body.email));
  }));

  router.get('/admin/tenants/:id/users', withAdmin(async ({ req, res, params, st }) => {
    sendJson(req, res, 200, { items: await st.userList.all(params.id) });
  }));

  router.post('/admin/users/:id/reset', withAdmin(async ({ req, res, params, db, st, config }) => {
    sendJson(req, res, 200, await resetUser(db, st, config, params.id));
  }));

  router.post('/admin/accessors', withAdmin(async ({ req, res, db, config }) => {
    const body = await readJson(req, config.maxJsonBytes);
    sendJson(req, res, 201, await createAccessor(db, { name: body.name, role: body.role }));
  }));

  router.get('/admin/accessors', withAdmin(async ({ req, res, st }) => sendJson(req, res, 200, { items: await st.accessorList.all() })));

  router.post('/admin/accessors/:id/revoke', withAdmin(async ({ req, res, params, db }) => {
    await revokeAccessor(db, params.id);
    sendJson(req, res, 200, { revoked: true });
  }));

  router.get('/admin/audit', withAdmin(async ({ req, res, url, st }) => {
    const limit = clampInt(url.searchParams.get('limit'), 1, 1000, 100);
    sendJson(req, res, 200, { items: await st.auditRecent.all(limit) });
  }));

  router.get('/admin/audit/verify', withAdmin(async ({ req, res, st }) => sendJson(req, res, 200, await verifyAudit(st))));
}
