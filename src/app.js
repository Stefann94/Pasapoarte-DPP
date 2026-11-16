import http from 'node:http';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { openDb, prepareStatements } from './db.js';
import { createBlobStore } from './blobstore.js';
import { applySecurityHeaders, clientIp, createRateLimiter, createRouter, HttpError, sendHtml, sendJson, wantsJson } from './http.js';
import { createSnapshotCache } from './passports.js';
import { pickLang, renderErrorPage } from './views.js';
import { registerAdminRoutes } from './routes/admin.js';
import { registerTenantRoutes } from './routes/tenant.js';
import { registerPublicRoutes } from './routes/public.js';

export function createApp(config) {
  mkdirSync(config.dataDir, { recursive: true });
  const db = openDb(path.join(config.dataDir, 'dpp.sqlite'));
  const st = prepareStatements(db);
  const blobs = createBlobStore(path.join(config.dataDir, 'blobs'));
  const snapshots = createSnapshotCache(st);
  const limiter = createRateLimiter({ windowMs: 60_000, max: config.rateLimitPerMinute });

  const router = createRouter();
  registerAdminRoutes(router);
  registerTenantRoutes(router);
  registerPublicRoutes(router);

  const sweep = setInterval(() => st.sessionSweep.run(Date.now()), 10 * 60_000);
  sweep.unref();

  const server = http.createServer(async (req, res) => {
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
      const isPage = (url.pathname === '/' || url.pathname.startsWith('/p/')) && !wantsJson(req, url);
      if (isPage) sendHtml(req, res, status, renderErrorPage({ lang: pickLang(req, url), status, message }));
      else sendJson(req, res, status, { error: code, message });
    }
  });
  server.keepAliveTimeout = 65_000; // longer than typical load balancer idle timeouts

  return {
    server,
    db,
    close() {
      clearInterval(sweep);
      limiter.stop();
      server.close();
      server.closeAllConnections?.();
      db.close();
    },
  };
}
