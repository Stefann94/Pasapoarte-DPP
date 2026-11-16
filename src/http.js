import { brotliCompressSync, constants as zc, gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';

export class HttpError extends Error {
  constructor(status, code, message) {
    super(message ?? code);
    this.status = status;
    this.code = code;
  }
}

export const badRequest = (message) => new HttpError(400, 'invalid_request', message);

// ---------------------------------------------------------------- routing

export function createRouter() {
  const routes = [];
  const add = (method) => (pattern, handler) => {
    const keys = [];
    const source = pattern.replace(/:(\w+)/g, (_, k) => {
      keys.push(k);
      return '([^/]+)';
    });
    routes.push({ method, re: new RegExp(`^${source}/?$`), keys, handler });
  };
  return {
    get: add('GET'),
    post: add('POST'),
    put: add('PUT'),
    delete: add('DELETE'),
    /** Returns {handler, params}, 'METHOD' (path exists, wrong verb) or null. */
    match(method, pathname) {
      const verb = method === 'HEAD' ? 'GET' : method;
      let pathExists = false;
      for (const r of routes) {
        const m = r.re.exec(pathname);
        if (!m) continue;
        pathExists = true;
        if (r.method !== verb) continue;
        const params = {};
        try {
          r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
        } catch {
          throw badRequest('Malformed URL encoding');
        }
        return { handler: r.handler, params };
      }
      return pathExists ? 'METHOD' : null;
    },
  };
}

// ---------------------------------------------------------------- request bodies

export async function readBody(req, limit) {
  const declared = Number(req.headers['content-length']);
  const tooLarge = () => new HttpError(413, 'payload_too_large', `Body exceeds ${limit} bytes`);
  if (Number.isFinite(declared) && declared > limit) throw tooLarge();
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw tooLarge();
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

export async function readJson(req, limit) {
  const type = req.headers['content-type'] ?? '';
  if (!type.toLowerCase().startsWith('application/json')) {
    throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json');
  }
  let value;
  try {
    value = JSON.parse((await readBody(req, limit)).toString('utf8'));
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw badRequest('Body is not valid JSON');
  }
  if (!isPlainObject(value)) throw badRequest('JSON body must be an object');
  return value;
}

export async function readForm(req, limit) {
  return new URLSearchParams((await readBody(req, limit)).toString('utf8'));
}

export const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// ---------------------------------------------------------------- responses

const COMPRESS_MIN_BYTES = 1024;

export const etagOf = (buf) => `"${createHash('sha1').update(buf).digest('base64url')}"`;

/**
 * A response body prepared for repeated sending: ETag computed once and
 * compressed variants created lazily and kept (used by the page cache).
 */
export function preparedBody(content, contentType) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
  return { body, contentType, etag: etagOf(body), br: null, gzip: null };
}

function pickEncoding(req, prepared) {
  if (prepared.body.length < COMPRESS_MIN_BYTES) return null;
  const accept = req.headers['accept-encoding'] ?? '';
  if (/\bbr\b/.test(accept)) return 'br';
  if (/\bgzip\b/.test(accept)) return 'gzip';
  return null;
}

/** Sends a prepared body with ETag/304 support and br/gzip compression. */
export function sendPrepared(req, res, status, prepared, headers = {}) {
  res.setHeader('Content-Type', prepared.contentType);
  res.setHeader('ETag', prepared.etag);
  res.setHeader('Vary', ['Accept-Encoding', headers.Vary].filter(Boolean).join(', '));
  for (const [k, v] of Object.entries(headers)) if (k !== 'Vary') res.setHeader(k, v);

  const inm = req.headers['if-none-match'];
  if (status === 200 && inm && inm.split(',').some((t) => t.trim().replace(/^W\//, '') === prepared.etag)) {
    res.writeHead(304);
    res.end();
    return;
  }
  const encoding = pickEncoding(req, prepared);
  let payload = prepared.body;
  if (encoding === 'br') {
    prepared.br ??= brotliCompressSync(prepared.body, {
      params: { [zc.BROTLI_PARAM_QUALITY]: 5, [zc.BROTLI_PARAM_SIZE_HINT]: prepared.body.length },
    });
    payload = prepared.br;
  } else if (encoding === 'gzip') {
    prepared.gzip ??= gzipSync(prepared.body, { level: 6 });
    payload = prepared.gzip;
  }
  if (encoding) res.setHeader('Content-Encoding', encoding);
  res.setHeader('Content-Length', payload.length);
  res.writeHead(status);
  res.end(req.method === 'HEAD' ? undefined : payload);
}

export function sendJson(req, res, status, value, headers = {}) {
  sendPrepared(req, res, status, preparedBody(JSON.stringify(value), 'application/json; charset=utf-8'), {
    'Cache-Control': 'no-store',
    ...headers,
  });
}

export function sendHtml(req, res, status, html, headers = {}) {
  sendPrepared(req, res, status, preparedBody(html, 'text/html; charset=utf-8'), {
    'Cache-Control': 'no-store',
    ...headers,
  });
}

export function redirect(res, location, headers = {}) {
  res.writeHead(303, { Location: location, 'Cache-Control': 'no-store', ...headers });
  res.end();
}

export function wantsJson(req, url) {
  const format = url.searchParams.get('format');
  if (format) return format === 'json';
  const accept = req.headers.accept ?? '';
  return accept.includes('application/json') && !accept.includes('text/html');
}

export function applySecurityHeaders(res, config) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  if (config.secureCookies) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

// ---------------------------------------------------------------- misc

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  }
  return req.socket.remoteAddress ?? 'unknown';
}

/** Fixed-window per-key rate limiter (in memory, per process). */
export function createRateLimiter({ windowMs, max }) {
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, e] of hits) if (now - e.start >= windowMs) hits.delete(k);
  }, windowMs);
  timer.unref();
  return {
    check(key) {
      const now = Date.now();
      let e = hits.get(key);
      if (!e || now - e.start >= windowMs) {
        e = { start: now, count: 0 };
        hits.set(key, e);
      }
      return ++e.count <= max;
    },
    stop: () => clearInterval(timer),
  };
}

export function clampInt(raw, min, max, fallback) {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}
