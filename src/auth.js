import { HttpError, parseCookies } from './http.js';
import { safeEqual, sha256 } from './crypto.js';

export const TENANT_KEY_PREFIX = 'dpk';
export const ACCESSOR_TOKEN_PREFIX = 'dpa';
export const SESSION_COOKIE = 'dpp_session';

/**
 * Access levels, lowest to highest. They follow the three audiences of the
 * Battery Regulation (Art. 77(2), Annex XIII): the public, persons with a
 * legitimate interest, and notified bodies / market surveillance authorities /
 * the Commission. The mapping is configurable once the Commission's
 * implementing rules on restricted access are final.
 */
export const LEVELS = ['public', 'legitimate_interest', 'authority'];
export const canSee = (viewer, required) => LEVELS.indexOf(viewer) >= LEVELS.indexOf(required);

const unauthorized = (msg = 'Missing or invalid credentials') => new HttpError(401, 'unauthorized', msg);

export function bearer(req) {
  const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization ?? '');
  return m ? m[1] : null;
}

export function requireAdmin(req, config) {
  const token = bearer(req);
  if (!token || !safeEqual(token, config.adminToken)) throw unauthorized();
}

/**
 * Authenticates a client (economic operator) API key. A suspended tenant can
 * still read and export its data (portability) but cannot change anything.
 */
export async function requireTenant(req, st, { write = false } = {}) {
  const token = bearer(req);
  if (!token?.startsWith(`${TENANT_KEY_PREFIX}_`)) throw unauthorized();
  const row = await st.apiKeyAuth.get(sha256(token));
  if (!row) throw unauthorized();
  if (write && row.status !== 'active') {
    throw new HttpError(403, 'tenant_suspended', 'Account is suspended: passports stay public, changes are disabled');
  }
  return { ...row, actor: `key:${row.keyId}` };
}

/** Returns the accessor (from bearer token or session cookie) or null for anonymous visitors. */
export async function findAccessor(req, st) {
  const token = bearer(req);
  if (token) {
    if (!token.startsWith(`${ACCESSOR_TOKEN_PREFIX}_`)) throw unauthorized();
    const accessor = await st.accessorByToken.get(sha256(token));
    if (!accessor) throw unauthorized('Access token is invalid or revoked');
    return accessor;
  }
  const sid = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!sid) return null;
  return (await st.sessionAccessor.get(sha256(sid), Date.now())) ?? null;
}
