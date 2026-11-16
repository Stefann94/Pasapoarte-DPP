import { randomBytes } from 'node:crypto';
import { findAccessor, canSee, SESSION_COOKIE } from '../auth.js';
import { sha256 } from '../crypto.js';
import { HttpError, preparedBody, readForm, redirect, sendHtml, sendJson, sendPrepared, wantsJson } from '../http.js';
import { buildView, INLINE_DOCUMENT_TYPES } from '../passports.js';
import { pickLang, renderLanding, renderPassportPage } from '../views.js';

const notFound = () => new HttpError(404, 'passport_not_found', 'Passport not found');

function sessionCookie(config, value, maxAgeSec) {
  return [
    `${SESSION_COOKIE}=${value}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`,
    config.secureCookies ? 'Secure' : null,
  ]
    .filter(Boolean)
    .join('; ');
}

export function registerPublicRoutes(router) {
  router.get('/', ({ req, res, url }) => {
    sendHtml(req, res, 200, renderLanding(pickLang(req, url)), { 'Cache-Control': 'public, max-age=3600' });
  });

  router.get('/healthz', ({ req, res, st }) => {
    st.auditLast.get();
    sendJson(req, res, 200, { status: 'ok' });
  });

  // The URL behind the QR code. Anonymous responses (the hot path) are cached
  // per passport revision, already serialised and compressed.
  router.get('/p/:id', ({ req, res, url, params, st, config, snapshots }) => {
    const loaded = snapshots.load(params.id);
    if (!loaded) throw notFound();
    const { passport, snapshot } = loaded;
    const accessor = findAccessor(req, st);
    const level = accessor?.role ?? 'public';
    const json = wantsJson(req, url);
    const lang = pickLang(req, url);
    const headers = { Vary: 'Accept, Accept-Language, Cookie, Authorization' };

    if (!accessor) {
      const key = json ? 'json' : `html:${lang}`;
      let prepared = snapshot.rendered.get(key);
      if (!prepared) {
        const view = buildView(config, passport, snapshot, 'public');
        prepared = json
          ? preparedBody(JSON.stringify(view), 'application/json; charset=utf-8')
          : preparedBody(renderPassportPage({ view, accessor: null, lang, error: false }), 'text/html; charset=utf-8');
        snapshot.rendered.set(key, prepared);
      }
      return sendPrepared(req, res, 200, prepared, { ...headers, 'Cache-Control': 'public, no-cache' });
    }

    const view = buildView(config, passport, snapshot, level);
    const restricted = { ...headers, 'Cache-Control': 'private, no-store' };
    if (json) return sendJson(req, res, 200, view, restricted);
    sendHtml(req, res, 200, renderPassportPage({ view, accessor, lang, error: false }), restricted);
  });

  router.post('/p/:id/access', async ({ req, res, url, params, st, config, snapshots }) => {
    const loaded = snapshots.load(params.id);
    if (!loaded) throw notFound();
    const lang = pickLang(req, url);
    const token = (await readForm(req, 4096)).get('token')?.trim() ?? '';
    const accessor = token ? st.accessorByToken.get(sha256(token)) : null;
    if (!accessor) {
      const view = buildView(config, loaded.passport, loaded.snapshot, 'public');
      return sendHtml(req, res, 401, renderPassportPage({ view, accessor: null, lang, error: true }));
    }
    const sid = randomBytes(32).toString('base64url');
    st.sessionInsert.run(sha256(sid), accessor.id, Date.now() + config.sessionTtlMs);
    redirect(res, `/p/${encodeURIComponent(params.id)}?lang=${lang}`, {
      'Set-Cookie': sessionCookie(config, sid, Math.floor(config.sessionTtlMs / 1000)),
    });
  });

  router.post('/p/:id/logout', ({ req, res, url, params, st, config }) => {
    const sid = /(?:^|;\s*)dpp_session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    if (sid) st.sessionDelete.run(sha256(sid));
    redirect(res, `/p/${encodeURIComponent(params.id)}?lang=${pickLang(req, url)}`, {
      'Set-Cookie': sessionCookie(config, '', 0),
    });
  });

  router.get('/p/:id/documents/:docId', async ({ req, res, params, st, blobs }) => {
    const passport = st.passportById.get(params.id);
    if (!passport) throw notFound();
    const doc = st.docGet.get(params.docId, passport.id);
    if (!doc) throw new HttpError(404, 'document_not_found', 'Document not found');
    const accessor = findAccessor(req, st);
    const level = accessor?.role ?? 'public';
    if (!canSee(level, doc.access)) {
      throw accessor
        ? new HttpError(403, 'forbidden', 'Your access level does not include this document')
        : new HttpError(401, 'unauthorized', 'This document requires restricted access');
    }

    const etag = `"${doc.sha256}"`; // content-addressed: the hash is a perfect ETag
    const isPublic = doc.access === 'public';
    const inline = INLINE_DOCUMENT_TYPES.has(doc.content_type);
    res.setHeader('ETag', etag);
    res.setHeader('Cache-Control', isPublic ? 'public, max-age=86400' : 'private, no-cache');
    if (!isPublic) res.setHeader('Vary', 'Cookie, Authorization');
    // Uploaded files never run as active content on this origin.
    res.setHeader(
      'Content-Security-Policy',
      doc.content_type === 'application/pdf' ? "default-src 'none'; frame-ancestors 'none'" : "sandbox; default-src 'none'",
    );
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304);
      return res.end();
    }
    res.setHeader('Content-Type', doc.content_type);
    res.setHeader('Content-Length', doc.size);
    res.setHeader(
      'Content-Disposition',
      `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(doc.name)}`,
    );
    res.writeHead(200);
    if (req.method === 'HEAD') return res.end();
    const stream = blobs.stream(doc.sha256);
    stream.on('error', (err) => {
      console.error('document stream failed', doc.id, err);
      res.destroy(err);
    });
    stream.pipe(res);
  });
}
