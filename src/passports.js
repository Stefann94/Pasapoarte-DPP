import { randomUUID } from 'node:crypto';
import { badRequest, HttpError, isPlainObject } from './http.js';
import { canonicalJson, sha256 } from './crypto.js';
import { canSee, LEVELS } from './auth.js';
import { isUniqueViolation, tx } from './db.js';
import { appendAudit } from './audit.js';
import { createLru } from './lru.js';

export const CATEGORIES = ['ev', 'lmt', 'industrial'];
export const PASSPORT_ID_RE = /^[A-Za-z0-9._~-]{8,128}$/;
const DATA_SECTIONS = ['public', 'legitimateInterest', 'authorities'];
const MAX_DEPTH = 16;

/** Document types accepted for upload, with a magic-byte check where it is cheap. */
export const DOCUMENT_TYPES = {
  'application/pdf': (b) => b.subarray(0, 5).toString('latin1') === '%PDF-',
  'image/png': (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  'image/jpeg': (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  'image/webp': (b) => b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP',
  'application/json': () => true,
  'text/csv': () => true,
  'text/plain': () => true,
};
export const INLINE_DOCUMENT_TYPES = new Set(['application/pdf', 'image/png', 'image/jpeg', 'image/webp']);

// ---------------------------------------------------------------- validation

function checkDepth(value, depth) {
  if (depth > MAX_DEPTH) throw badRequest(`data is nested deeper than ${MAX_DEPTH} levels`);
  if (value !== null && typeof value === 'object') {
    for (const v of Array.isArray(value) ? value : Object.values(value)) checkDepth(v, depth + 1);
  }
}

/**
 * Structural validation only: the platform checks that the passport is well
 * formed, it does not certify that the declared values are true. The client
 * (economic operator) remains responsible for the content.
 */
export function normalizeData(data) {
  if (!isPlainObject(data)) throw badRequest('data must be an object');
  for (const key of Object.keys(data)) {
    if (!DATA_SECTIONS.includes(key)) {
      throw badRequest(`Unknown data section "${key}". Allowed: ${DATA_SECTIONS.join(', ')}`);
    }
  }
  if (!isPlainObject(data.public)) throw badRequest('data.public must be an object');
  for (const key of ['legitimateInterest', 'authorities']) {
    if (data[key] !== undefined && !isPlainObject(data[key])) throw badRequest(`data.${key} must be an object`);
  }
  checkDepth(data, 0);
  return {
    public: data.public,
    legitimateInterest: data.legitimateInterest ?? {},
    authorities: data.authorities ?? {},
  };
}

export function validatePassportFields({ id, productIdentifier, category }) {
  if (id !== undefined && (typeof id !== 'string' || !PASSPORT_ID_RE.test(id))) {
    throw badRequest('id must be 8-128 characters: letters, digits, . _ ~ -');
  }
  if (typeof productIdentifier !== 'string' || !productIdentifier.trim() || productIdentifier.length > 200) {
    throw badRequest('productIdentifier must be a non-empty string (max 200 characters)');
  }
  if (!CATEGORIES.includes(category)) throw badRequest(`category must be one of: ${CATEGORIES.join(', ')}`);
}

export function validateNote(note) {
  if (note === undefined || note === null) return null;
  if (typeof note !== 'string' || note.length > 1000) throw badRequest('note must be a string (max 1000 characters)');
  return note;
}

export function validateAccess(access) {
  if (!LEVELS.includes(access)) throw badRequest(`access must be one of: ${LEVELS.join(', ')}`);
  return access;
}

export function validateDocumentName(name) {
  if (typeof name !== 'string' || !name.trim() || name.length > 200 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw badRequest('Document name must be 1-200 printable characters');
  }
  return name.trim();
}

export const hashData = (data) => sha256(canonicalJson(data));

// ---------------------------------------------------------------- writes

const conflict = (message) => new HttpError(409, 'conflict', message);

export async function createPassport(db, { tenant, id, productIdentifier, category, data, note }) {
  validatePassportFields({ id, productIdentifier, category });
  const normalized = normalizeData(data);
  const cleanNote = validateNote(note);
  const passportId = id ?? randomUUID();
  const now = new Date().toISOString();
  const dataHash = hashData(normalized);
  const actor = `key:${tenant.keyId}`;
  try {
    await tx(db, async (st) => {
      await st.passportInsert.run(passportId, tenant.tenantId, productIdentifier, category, 1, now, now);
      await st.versionInsert.run(passportId, 1, JSON.stringify(normalized), dataHash, cleanNote, now, actor);
      await appendAudit(st, { actor, action: 'passport.created', target: passportId, details: { version: 1, dataHash } });
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw conflict('A passport with this id or productIdentifier already exists');
    throw err;
  }
  return { id: passportId, version: 1, dataHash };
}

export async function addVersion(db, { tenant, passport, data, note, expectedVersion }) {
  const normalized = normalizeData(data);
  const cleanNote = validateNote(note);
  const dataHash = hashData(normalized);
  const actor = `key:${tenant.keyId}`;
  return tx(db, async (st) => {
    // Row lock: concurrent updates of the same passport are serialised.
    const current = await st.passportLockForUpdate.get(passport.id);
    if (expectedVersion !== undefined && expectedVersion !== current.current_version) {
      throw conflict(`expectedVersion ${expectedVersion} does not match current version ${current.current_version}`);
    }
    const latest = await st.versionGet.get(passport.id, current.current_version);
    if (latest.data_hash === dataHash) return { id: passport.id, version: current.current_version, dataHash, changed: false };
    const version = current.current_version + 1;
    const now = new Date().toISOString();
    await st.versionInsert.run(passport.id, version, JSON.stringify(normalized), dataHash, cleanNote, now, actor);
    await st.passportBump.run(version, now, passport.id);
    await appendAudit(st, { actor, action: 'passport.updated', target: passport.id, details: { version, dataHash } });
    return { id: passport.id, version, dataHash, changed: true };
  });
}

// ---------------------------------------------------------------- reads

export async function ownPassport(st, tenant, id) {
  const p = await st.passportById.get(id);
  if (!p || p.tenant_id !== tenant.tenantId) throw new HttpError(404, 'passport_not_found', 'Passport not found');
  return p;
}

export const passportUrl = (config, id) => `${config.baseUrl}/p/${encodeURIComponent(id)}`;
export const documentUrl = (config, passportId, docId) =>
  `${passportUrl(config, passportId)}/documents/${encodeURIComponent(docId)}`;

export const documentJson = (config, passportId, d) => ({
  id: d.id,
  name: d.name,
  contentType: d.content_type,
  size: d.size,
  sha256: d.sha256,
  access: d.access,
  createdAt: d.created_at,
  url: documentUrl(config, passportId, d.id),
});

/**
 * Snapshot cache for the public read path (QR scans).
 *  - A miss loads passport + current version + documents in ONE query.
 *  - A hit younger than ttlMs is served with zero database round trips.
 *  - An older hit costs one tiny primary-key lookup (rev check); versions are
 *    immutable and every change bumps passports.rev, so this is always correct,
 *    also with several server instances sharing the database.
 *  - Writes on this instance call invalidate(), so they show up immediately.
 * Each snapshot also stores its rendered, compressed responses.
 */
export function createSnapshotCache(st, { max = 10_000, ttlMs = 2000 } = {}) {
  const lru = createLru(max);

  async function fetchFresh(id) {
    const row = await st.snapshotLoad.get(id);
    if (!row) return null;
    const { data, data_hash, documents_json, ...passport } = row;
    const parsed = JSON.parse(data);
    const snap = {
      passport,
      rev: passport.rev,
      version: passport.current_version,
      updatedAt: passport.updated_at,
      dataHash: data_hash,
      data: parsed,
      publicHash: hashData(parsed.public),
      documents: JSON.parse(documents_json),
      rendered: new Map(),
      checkedAt: Date.now(),
    };
    lru.set(id, snap);
    return snap;
  }

  return {
    /** Returns {passport, snapshot} or null if the passport does not exist. */
    async load(id) {
      let snap = lru.get(id);
      if (snap && Date.now() - snap.checkedAt > ttlMs) {
        const row = await st.passportRev.get(id);
        if (!row) {
          lru.delete(id);
          return null;
        }
        if (row.rev === snap.rev) snap.checkedAt = Date.now();
        else snap = null;
      }
      snap ??= await fetchFresh(id);
      return snap ? { passport: snap.passport, snapshot: snap } : null;
    },
    invalidate: (id) => lru.delete(id),
    get size() {
      return lru.size;
    },
  };
}

/** The passport as seen by a viewer at the given access level. */
export function buildView(config, passport, snap, level) {
  const data = { public: snap.data.public };
  if (canSee(level, 'legitimate_interest')) data.legitimateInterest = snap.data.legitimateInterest;
  if (canSee(level, 'authority')) data.authorities = snap.data.authorities;
  const view = {
    id: passport.id,
    url: passportUrl(config, passport.id),
    productIdentifier: passport.product_identifier,
    category: passport.category,
    version: snap.version,
    updatedAt: snap.updatedAt,
    accessLevel: level,
    integrity: { publicSha256: snap.publicHash },
    data,
    documents: snap.documents.filter((d) => canSee(level, d.access)).map((d) => documentJson(config, passport.id, d)),
  };
  if (level === 'authority') view.integrity.dataSha256 = snap.dataHash;
  return view;
}
