import { randomBytes } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { findAccessor, canSee, SESSION_COOKIE } from '../auth.js';
import { sha256 } from '../crypto.js';
import { HttpError, parseCookies, preparedBody, readForm, redirect, sendHtml, sendJson, sendPrepared, wantsJson } from '../http.js';
import { buildView, INLINE_DOCUMENT_TYPES, passportUrl } from '../passports.js';
import { pickLang, renderErrorPage, renderLanding, renderMirrorPage, renderPassportPage } from '../views.js';

const notFound = () => new HttpError(404, 'passport_not_found', 'Passport not found');

function sessionCookie(config, value, maxAgeSec) {
  return [`${SESSION_COOKIE}=${value}`, 'HttpOnly', 'Path=/', 'SameSite=Lax', `Max-Age=${maxAgeSec}`, config.secureCookies ? 'Secure' : null]
    .filter(Boolean)
    .join('; ');
}

/** Copy of an external passport archived in the EU, shown when its host is down. */
async function sendMirror({ req, res, json, lang, passport, snapshot, blobs, config }) {
  if (!passport.mirror_sha256) {
    const body = { error: 'temporarily_unavailable', message: 'The passport host is unavailable and no archived copy exists yet' };
    if (json) return sendJson(req, res, 503, body, { 'Retry-After': '300' });
    return sendHtml(req, res, 503, renderErrorPage({ lang, status: 503, message: body.message }), { 'Retry-After': '300' });
  }
  // Parse JSON copies once per revision.
  if (snapshot.mirrorParsed === undefined) {
    snapshot.mirrorParsed = null;
    if (passport.mirror_content_type?.includes('json')) {
      try {
        snapshot.mirrorParsed = JSON.parse((await blobs.get(passport.mirror_sha256)).toString('utf8'));
      } catch {
        snapshot.mirrorParsed = null;
      }
    }
  }
  const mirror = {
    externalUrl: passport.external_url,
    fetchedAt: passport.mirror_fetched_at,
    contentType: passport.mirror_content_type,
    sha256: passport.mirror_sha256,
    contentUrl: `/p/${encodeURIComponent(passport.id)}/mirror/content`,
    data: snapshot.mirrorParsed,
  };
  const headers = { 'Cache-Control': 'public, max-age=0, s-maxage=30' };
  if (json) {
    return sendJson(req, res, 200, {
      id: passport.id,
      url: passportUrl(config, passport.id),
      productIdentifier: passport.product_identifier,
      source: 'eu-mirror',
      mirror: { ...mirror, contentUrl: `${config.baseUrl}${mirror.contentUrl}` },
    }, headers);
  }
  sendHtml(req, res, 200, renderMirrorPage({ lang, passport, mirror }), headers);
}

export function registerPublicRoutes(router) {
  router.get('/', ({ req, res, url }) => {
    sendHtml(req, res, 200, renderLanding(pickLang(req, url)), { 'Cache-Control': 'public, max-age=3600' });
  });

  router.get('/healthz', async ({ req, res, st, db, blobs }) => {
    await st.ping.get();
    sendJson(req, res, 200, { status: 'ok', database: db.kind, storage: blobs.kind });
  });

  // The URL behind the QR code. Anonymous responses (the hot path) are cached
  // per passport revision, already serialised and compressed.
  router.get('/p/:id', async ({ req, res, url, params, st, config, snapshots, blobs }) => {
    const hasCredentials = Boolean(req.headers.authorization || parseCookies(req.headers.cookie)[SESSION_COOKIE]);
    const [loaded, accessor] = await Promise.all([
      snapshots.load(params.id),
      hasCredentials ? findAccessor(req, st) : null,
    ]);
    if (!loaded) throw notFound();
    const { passport, snapshot } = loaded;
    const json = wantsJson(req, url);
    const lang = pickLang(req, url);
    const headers = { Vary: 'Accept, Accept-Language, Cookie, Authorization' };

    // Externally hosted passport: the QR code points here (a domain the importer
    // controls). While the external host works, visitors are sent there in a
    // single https hop; when it is down they get the copy archived in the EU.
    if (passport.external_url) {
      const forceMirror = url.searchParams.get('mirror') === '1';
      if (!forceMirror && passport.mirror_status !== 'down') {
        res.writeHead(302, { Location: passport.external_url, 'Cache-Control': 'public, max-age=0, s-maxage=60' });
        return res.end();
      }
      return sendMirror({ req, res, json, lang, passport, snapshot, blobs, config });
    }

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
      // s-maxage lets the Vercel/CDN edge serve repeat scans without invoking the function.
      return sendPrepared(req, res, 200, prepared, {
        ...headers,
        'Cache-Control': hasCredentials ? 'private, no-cache' : 'public, max-age=0, s-maxage=10, stale-while-revalidate=60',
      });
    }

    const view = buildView(config, passport, snapshot, accessor.role);
    const restricted = { ...headers, 'Cache-Control': 'private, no-store' };
    if (json) return sendJson(req, res, 200, view, restricted);
    sendHtml(req, res, 200, renderPassportPage({ view, accessor, lang, error: false }), restricted);
  });

  // Archived bytes of an external passport (HTML is served sandboxed: no scripts).
  router.get('/p/:id/mirror/content', async ({ req, res, params, snapshots, blobs }) => {
    const loaded = await snapshots.load(params.id);
    const p = loaded?.passport;
    if (!p?.external_url || !p.mirror_sha256) throw new HttpError(404, 'mirror_not_found', 'No archived copy');
    const stream = await blobs.open(p.mirror_sha256);
    res.writeHead(200, {
      'Content-Type': p.mirror_content_type ?? 'application/octet-stream',
      'Content-Security-Policy': "sandbox; default-src 'none'; img-src * data:; style-src * 'unsafe-inline'; font-src *",
      'Cache-Control': 'public, max-age=300',
      ETag: `"${p.mirror_sha256}"`,
    });
    await pipeline(stream, res);
  });

  router.post('/p/:id/access', async ({ req, res, url, params, st, config, snapshots }) => {
    const loaded = await snapshots.load(params.id);
    if (!loaded) throw notFound();
    const lang = pickLang(req, url);
    const token = (await readForm(req, 4096)).get('token')?.trim() ?? '';
    const accessor = token ? await st.accessorByToken.get(sha256(token)) : null;
    if (!accessor) {
      const view = buildView(config, loaded.passport, loaded.snapshot, 'public');
      return sendHtml(req, res, 401, renderPassportPage({ view, accessor: null, lang, error: true }));
    }
    const sid = randomBytes(32).toString('base64url');
    await st.sessionInsert.run(sha256(sid), accessor.id, Date.now() + config.sessionTtlMs);
    redirect(res, `/p/${encodeURIComponent(params.id)}?lang=${lang}`, {
      'Set-Cookie': sessionCookie(config, sid, Math.floor(config.sessionTtlMs / 1000)),
    });
  });

  router.post('/p/:id/logout', async ({ req, res, url, params, st, config }) => {
    const sid = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (sid) await st.sessionDelete.run(sha256(sid));
    redirect(res, `/p/${encodeURIComponent(params.id)}?lang=${pickLang(req, url)}`, {
      'Set-Cookie': sessionCookie(config, '', 0),
    });
  });

  router.get('/p/:id/documents/:docId', async ({ req, res, params, st, blobs }) => {
    const doc = await st.docForPassport.get(params.docId, params.id);
    if (!doc) throw new HttpError(404, 'document_not_found', 'Document not found');
    const accessor = await findAccessor(req, st);
    const level = accessor?.role ?? 'public';
    if (!canSee(level, doc.access)) {
      throw accessor
        ? new HttpError(403, 'forbidden', 'Your access level does not include this document')
        : new HttpError(401, 'unauthorized', 'This document requires restricted access');
    }

    const etag = `"${doc.sha256}"`; // content-addressed: the hash is a perfect ETag
    const isPublic = doc.access === 'public';
    res.setHeader('ETag', etag);
    res.setHeader('Cache-Control', isPublic ? 'public, max-age=86400, s-maxage=86400' : 'private, no-cache');
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
    const stream = req.method === 'HEAD' ? null : await blobs.open(doc.sha256);
    res.setHeader('Content-Type', doc.content_type);
    res.setHeader('Content-Length', doc.size);
    res.setHeader(
      'Content-Disposition',
      `${INLINE_DOCUMENT_TYPES.has(doc.content_type) ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(doc.name)}`,
    );
    res.writeHead(200);
    if (!stream) return res.end();
    await pipeline(stream, res);
  });
}
