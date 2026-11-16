import http from 'node:http';
import { openDatabase, statements } from './db.js';
import { createBlobStore } from './blobstore.js';
import { applySecurityHeaders, clientIp, createRateLimiter, createRouter, HttpError, sendHtml, sendJson, wantsJson } from './http.js';
import { createSnapshotCache } from './passports.js';
import { pickLang, renderErrorPage } from './views.js';
import { registerAdminRoutes } from './routes/admin.js';
import { registerTenantRoutes } from './routes/tenant.js';
import { registerPublicRoutes } from './routes/public.js';
import { registerPortalRoutes } from './routes/portal.js';
import { registerConsoleRoutes } from './routes/console.js';

/**
 * Builds the application. Returns `handler` (a Node request listener, used
 * directly as the Vercel function) and `server` (for running it standalone).
 */
export async function createApp(config) {
  const db = await openDatabase(config);
  const st = statements(db);
  const blobs = createBlobStore(config);
  const snapshots = createSnapshotCache(st, { ttlMs: config.snapshotTtlMs });
  const limiter = createRateLimiter({ windowMs: 60_000, max: config.rateLimitPerMinute });

  const router = createRouter();
  registerAdminRoutes(router);
  registerTenantRoutes(router);
  registerPublicRoutes(router);
  registerPortalRoutes(router);
  registerConsoleRoutes(router);

  const sweep = setInterval(() => {
    const now = Date.now();
    st.sessionSweep.run(now).catch(() => {});
    st.portalSessionSweep.run(now).catch(() => {});
  }, 10 * 60_000);
  sweep.unref();

  async function handler(req, res) {
    applySecurityHeaders(res, config);
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (!limiter.check(clientIp(req, config.trustProxy))) {
        res.setHeader('Retry-After', '60');
        throw new HttpError(429, 'rate_limited', 'Too many requests');
      }
      const match = router.match(req.method ?? 'GET', url.pathname);
      if (match === null) throw new HttpError(404, 'not_found', 'Not found');
      if (match === 'METHOD') throw new HttpError(405, 'method_not_allowed', 'Method not allowed');
      await match.handler({ req, res, url, params: match.params, config, db, st, blobs, snapshots });
    } catch (err) {
      if (!(err instanceof HttpError)) console.error(err);
      if (res.headersSent) return void res.destroy();
      const status = err instanceof HttpError ? err.status : 500;
      const code = err instanceof HttpError ? err.code : 'internal_error';
      const message = err instanceof HttpError ? err.message : 'Internal server error';
      if (status === 413) res.setHeader('Connection', 'close');
      const isPage = (url.pathname === '/' || url.pathname.startsWith('/p/') || url.pathname.startsWith('/portal') || url.pathname.startsWith('/console')) && !wantsJson(req, url);
      if (isPage) sendHtml(req, res, status, renderErrorPage({ lang: pickLang(req, url), status, message }));
      else sendJson(req, res, status, { error: code, message });
    }
  }

  const server = http.createServer(handler);
  server.keepAliveTimeout = 65_000; // longer than typical load balancer idle timeouts

  return {
    handler,
    server,
    db,
    async close() {
      clearInterval(sweep);
      limiter.stop();
      server.close();
      server.closeAllConnections?.();
      await db.close();
    },
  };
}
