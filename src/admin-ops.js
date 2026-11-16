import { randomBytes, randomUUID } from 'node:crypto';
import { ACCESSOR_TOKEN_PREFIX, TENANT_KEY_PREFIX } from './auth.js';
import { appendAudit } from './audit.js';
import { newToken, sha256 } from './crypto.js';
import { isUniqueViolation, tx } from './db.js';
import { badRequest, HttpError } from './http.js';
import { isEmail, normalizeEmail, SETUP_TTL_MS } from './portal/auth.js';

/* Platform-operator operations, shared by the JSON admin API and the web console. */

const str = (v, field, max = 200, optional = false) => {
  if (optional && (v === undefined || v === null || v === '')) return null;
  if (typeof v !== 'string' || !v.trim() || v.length > max) throw badRequest(`${field} must be a non-empty string (max ${max})`);
  return v.trim();
};

export const setupLink = (config, token) => `${config.baseUrl}/portal/setup?token=${encodeURIComponent(token)}`;

export async function createTenant(db, { name, vatId }) {
  const cleanName = str(name, 'name');
  const cleanVat = str(vatId, 'vatId', 50, true);
  const id = randomUUID();
  const keyId = randomUUID();
  const apiKey = newToken(TENANT_KEY_PREFIX);
  const now = new Date().toISOString();
  const tenant = await tx(db, async (t) => {
    await t.tenantInsert.run(id, cleanName, cleanVat, now);
    await t.apiKeyInsert.run(keyId, id, sha256(apiKey), now);
    await appendAudit(t, { actor: 'admin', action: 'tenant.created', target: id, details: { name: cleanName, apiKeyId: keyId } });
    return t.tenantById.get(id);
  });
  return { tenant, apiKey: { id: keyId, token: apiKey } };
}

export async function createApiKey(db, st, tenantId) {
  if (!(await st.tenantById.get(tenantId))) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
  const keyId = randomUUID();
  const apiKey = newToken(TENANT_KEY_PREFIX);
  await tx(db, async (t) => {
    await t.apiKeyInsert.run(keyId, tenantId, sha256(apiKey), new Date().toISOString());
    await appendAudit(t, { actor: 'admin', action: 'apikey.created', target: tenantId, details: { apiKeyId: keyId } });
  });
  return { id: keyId, token: apiKey };
}

export async function revokeApiKey(db, keyId) {
  const ok = await tx(db, async (t) => {
    if (!(await t.apiKeyRevoke.run(new Date().toISOString(), keyId)).changes) return false;
    await appendAudit(t, { actor: 'admin', action: 'apikey.revoked', target: keyId });
    return true;
  });
  if (!ok) throw new HttpError(404, 'api_key_not_found', 'API key not found or already revoked');
}

/** Suspension blocks changes only: passports stay public (availability must not depend on payment). */
export async function setTenantStatus(db, tenantId, action) {
  const status = action === 'suspend' ? 'suspended' : 'active';
  const tenant = await tx(db, async (t) => {
    if (!(await t.tenantSetStatus.run(status, tenantId)).changes) return null;
    await appendAudit(t, { actor: 'admin', action: `tenant.${action}`, target: tenantId });
    return t.tenantById.get(tenantId);
  });
  if (!tenant) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
  return tenant;
}

/** Creates a portal user; the person sets their own password via a one-time link (7 days). */
export async function createUser(db, st, config, tenantId, rawEmail) {
  if (!(await st.tenantById.get(tenantId))) throw new HttpError(404, 'tenant_not_found', 'Tenant not found');
  const email = normalizeEmail(rawEmail);
  if (!isEmail(email)) throw badRequest('email is not valid');
  const id = randomUUID();
  const token = randomBytes(32).toString('base64url');
  try {
    await tx(db, async (t) => {
      await t.userInsert.run(id, tenantId, email, sha256(token), Date.now() + SETUP_TTL_MS, new Date().toISOString());
      await appendAudit(t, { actor: 'admin', action: 'user.created', target: id, details: { tenantId } });
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw new HttpError(409, 'conflict', 'A user with this email already exists');
    throw err;
  }
  return { user: { id, email, tenantId }, setupUrl: setupLink(config, token), expiresInDays: 7 };
}

/** New one-time link (e.g. forgotten password). Existing sessions are closed. */
export async function resetUser(db, st, config, userId) {
  if (!(await st.userById.get(userId))) throw new HttpError(404, 'user_not_found', 'User not found');
  const token = randomBytes(32).toString('base64url');
  await tx(db, async (t) => {
    await t.userResetSetup.run(sha256(token), Date.now() + SETUP_TTL_MS, userId);
    await t.portalSessionDeleteForUser.run(userId);
    await appendAudit(t, { actor: 'admin', action: 'user.reset', target: userId });
  });
  return { setupUrl: setupLink(config, token), expiresInDays: 7 };
}

/**
 * Organisations with restricted access (authorities, recyclers, repairers...),
 * onboarded after their identity and legitimate interest have been verified.
 */
export async function createAccessor(db, { name, role }) {
  const cleanName = str(name, 'name');
  if (!['legitimate_interest', 'authority'].includes(role)) throw badRequest('role must be legitimate_interest or authority');
  const id = randomUUID();
  const token = newToken(ACCESSOR_TOKEN_PREFIX);
  await tx(db, async (t) => {
    await t.accessorInsert.run(id, cleanName, role, sha256(token), new Date().toISOString());
    await appendAudit(t, { actor: 'admin', action: 'accessor.created', target: id, details: { name: cleanName, role } });
  });
  return { accessor: { id, name: cleanName, role }, token };
}

export async function revokeAccessor(db, accessorId) {
  const ok = await tx(db, async (t) => {
    if (!(await t.accessorRevoke.run(new Date().toISOString(), accessorId)).changes) return false;
    await t.sessionDeleteForAccessor.run(accessorId);
    await appendAudit(t, { actor: 'admin', action: 'accessor.revoked', target: accessorId });
    return true;
  });
  if (!ok) throw new HttpError(404, 'accessor_not_found', 'Accessor not found or already revoked');
}
