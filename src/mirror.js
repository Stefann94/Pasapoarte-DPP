import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { sha256 } from './crypto.js';
import { badRequest } from './http.js';

/*
 * EU mirror for passports hosted elsewhere (typically by a non-EU manufacturer).
 *
 * The Batteries Regulation makes the importer responsible for the passport
 * staying available (Art. 78(e)) even when someone else hosts it. This module
 * periodically takes a copy of the external passport, keeps it in EU storage,
 * and lets the public route fall back to it when the external host fails.
 */

const MAX_BYTES = 10 * 1024 * 1024;
const TIMEOUT_MS = 8_000;
const MAX_REDIRECTS = 3;

export function validateExternalUrl(raw, { allowInsecure = false } = {}) {
  if (typeof raw !== 'string' || raw.length > 2000) throw badRequest('externalUrl must be a URL (max 2000 characters)');
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    throw badRequest('externalUrl is not a valid URL');
  }
  if (url.protocol !== 'https:' && !(allowInsecure && url.protocol === 'http:')) {
    throw badRequest('externalUrl must use https');
  }
  if (url.username || url.password) throw badRequest('externalUrl must not contain credentials');
  return url.toString();
}

// ---------------------------------------------------------------- SSRF protection

function isPrivateV4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 169 && b === 254) || // link-local / cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224 // multicast + reserved
  );
}

function isPrivateIp(ip) {
  if (isIP(ip) === 4) return isPrivateV4(ip);
  const v6 = ip.toLowerCase();
  if (v6.startsWith('::ffff:')) return isPrivateV4(v6.slice(7));
  return v6 === '::' || v6 === '::1' || v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80') || v6.startsWith('ff');
}

/** Refuses hosts that resolve to private, loopback or metadata addresses. */
async function assertPublicHost(url, allowPrivate) {
  if (allowPrivate) return;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = isIP(host) ? [{ address: host }] : await lookup(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((a) => isPrivateIp(a.address))) {
    throw new Error('host resolves to a non-public address');
  }
}

/**
 * Fetches an external passport with strict limits: public hosts only, few
 * redirects (each re-validated), timeout and size cap.
 */
export async function fetchExternal(rawUrl, { allowPrivate = false, allowInsecure = false } = {}) {
  let url = new URL(validateExternalUrl(rawUrl, { allowInsecure }));
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertPublicHost(url, allowPrivate);
    const res = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { Accept: 'application/json, text/html;q=0.9, */*;q=0.5', 'User-Agent': 'dpp-eu-mirror/1.0' },
    });
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      url = new URL(validateExternalUrl(new URL(res.headers.get('location'), url).toString(), { allowInsecure }));
      await res.body?.cancel();
      continue;
    }
    if (!res.ok) {
      await res.body?.cancel();
      return { ok: false, httpStatus: res.status, error: `HTTP ${res.status}` };
    }
    const declared = Number(res.headers.get('content-length'));
    if (declared > MAX_BYTES) {
      await res.body?.cancel();
      return { ok: false, httpStatus: res.status, error: 'response too large' };
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > MAX_BYTES) return { ok: false, httpStatus: res.status, error: 'response too large' };
      chunks.push(chunk);
    }
    const buf = Buffer.concat(chunks);
    if (!buf.length) return { ok: false, httpStatus: res.status, error: 'empty response' };
    const contentType = (res.headers.get('content-type') ?? 'application/octet-stream').split(';')[0].trim().toLowerCase();
    return { ok: true, httpStatus: res.status, contentType, buf };
  }
  return { ok: false, error: 'too many redirects' };
}

// ---------------------------------------------------------------- checks

/**
 * Checks one external passport, stores a new copy if the content changed, and
 * records status/content changes. Returns the new status.
 */
export async function checkMirror(st, blobs, config, passport) {
  const now = new Date().toISOString();
  let result;
  try {
    result = await fetchExternal(passport.external_url, {
      allowPrivate: config.mirrorAllowPrivate,
      allowInsecure: config.mirrorAllowPrivate,
    });
  } catch (err) {
    result = { ok: false, error: err.name === 'TimeoutError' ? 'timeout' : String(err.message ?? err).slice(0, 200) };
  }

  const status = result.ok ? 'ok' : 'down';
  let hash = null;
  if (result.ok) hash = await blobs.put(result.buf);
  const statusChanged = status !== passport.mirror_status;
  const contentChanged = Boolean(hash && hash !== passport.mirror_sha256);

  await st.mirrorUpdate.run(
    status,
    now,
    result.ok ? null : result.error,
    hash,
    result.ok ? result.contentType : null,
    result.ok ? now : null,
    statusChanged || contentChanged,
    passport.id,
  );
  if (statusChanged || contentChanged) {
    await st.mirrorEventInsert.run(
      randomUUID(),
      passport.id,
      now,
      status,
      result.httpStatus ?? null,
      hash,
      result.ok ? result.contentType : null,
      result.ok ? result.buf.length : null,
      result.ok ? null : result.error,
    );
  }
  return { status, contentChanged, error: result.ok ? null : result.error };
}

/** Checks the passports whose last check is older than `staleMs`, a few at a time. */
export async function runDueChecks(
  st,
  blobs,
  config,
  { staleMs = 12 * 60 * 60 * 1000, limit = 200, concurrency = 12, budgetMs = 18_000 } = {},
) {
  // Stops starting new checks after budgetMs, so the run fits a serverless
  // time limit; the rest are picked up by the next run (oldest first).
  const deadline = Date.now() + budgetMs;
  const due = await st.mirrorDue.all(new Date(Date.now() - staleMs).toISOString(), limit);
  const summary = { checked: 0, ok: 0, down: 0, changed: 0, remaining: 0 };
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, due.length) }, async () => {
      while (next < due.length && Date.now() < deadline) {
        const p = due[next++];
        const r = await checkMirror(st, blobs, config, p);
        summary.checked++;
        summary[r.status]++;
        if (r.contentChanged) summary.changed++;
      }
    }),
  );
  summary.remaining = due.length - summary.checked;
  return summary;
}

export const mirrorEventJson = (e) => ({
  at: e.at,
  status: e.status,
  httpStatus: e.http_status,
  sha256: e.sha256,
  contentType: e.content_type,
  size: e.size,
  error: e.error,
});

export const mirrorJson = (p) => ({
  externalUrl: p.external_url,
  status: p.mirror_status ?? 'unchecked',
  checkedAt: p.mirror_checked_at,
  lastCopyAt: p.mirror_fetched_at,
  lastCopySha256: p.mirror_sha256,
  lastCopyContentType: p.mirror_content_type,
  error: p.mirror_error,
});
