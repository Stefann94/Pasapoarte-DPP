import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { sha256 } from '../crypto.js';
import { HttpError, parseCookies } from '../http.js';

const scrypt = promisify(scryptCb);
const PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
export const PORTAL_COOKIE = 'dpp_portal';
export const PORTAL_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const SETUP_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MIN_PASSWORD = 10;

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize('NFKC'), salt, 32, PARAMS);
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

// Used when the e-mail does not exist, so response time does not reveal which accounts exist.
const DUMMY_HASH = await hashPassword(randomBytes(16).toString('hex'));

export async function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, key] = (stored ?? DUMMY_HASH).split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(key, 'base64url');
  const actual = await scrypt(password.normalize('NFKC'), Buffer.from(salt, 'base64url'), expected.length, {
    N: Number(N),
    r: Number(r),
    p: Number(p),
    maxmem: PARAMS.maxmem,
  });
  return stored !== undefined && stored !== null && timingSafeEqual(actual, expected);
}

export const normalizeEmail = (email) => String(email ?? '').trim().toLowerCase();
export const isEmail = (email) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(email);

export function portalCookie(config, value, maxAgeSec) {
  return [`${PORTAL_COOKIE}=${value}`, 'HttpOnly', 'Path=/portal', 'SameSite=Lax', `Max-Age=${maxAgeSec}`, config.secureCookies ? 'Secure' : null]
    .filter(Boolean)
    .join('; ');
}

export async function createPortalSession(st, userId) {
  const sid = randomBytes(32).toString('base64url');
  await st.portalSessionInsert.run(sha256(sid), userId, Date.now() + PORTAL_SESSION_TTL_MS);
  return sid;
}

/** The logged-in portal user as a "tenant" usable by the passport/model services, or null. */
export async function portalUser(req, st) {
  const sid = parseCookies(req.headers.cookie)[PORTAL_COOKIE];
  if (!sid) return null;
  const row = await st.portalSessionUser.get(sha256(sid), Date.now());
  if (!row) return null;
  return {
    userId: row.id,
    email: row.email,
    tenantId: row.tenantId,
    tenantName: row.tenantName,
    status: row.status,
    actor: `user:${row.id}`,
    sid,
  };
}

/**
 * Blocks cross-site form posts. Session cookies are already SameSite=Lax;
 * this also rejects any POST whose Origin is a different site.
 */
export function checkOrigin(req, config) {
  const origin = req.headers.origin;
  if (!origin || origin === 'null') {
    if (origin === 'null') throw new HttpError(403, 'bad_origin', 'Cross-site request blocked');
    return;
  }
  let host;
  try {
    host = new URL(origin).host;
  } catch {
    throw new HttpError(403, 'bad_origin', 'Cross-site request blocked');
  }
  const allowed = new Set([new URL(config.baseUrl).host, req.headers.host, req.headers['x-forwarded-host']].filter(Boolean));
  if (!allowed.has(host)) throw new HttpError(403, 'bad_origin', 'Cross-site request blocked');
}
