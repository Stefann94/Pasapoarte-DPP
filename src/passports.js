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

export function createPassport(db, st, { tenant, id, productIdentifier, category, data, note }) {
  validatePassportFields({ id, productIdentifier, category });
  const normalized = normalizeData(data);
  const passportId = id ?? randomUUID();
  const now = new Date().toISOString();
  const dataHash = hashData(normalized);
  const actor = `key:${tenant.keyId}`;
  try {
    tx(db, () => {
      st.passportInsert.run(passportId, tenant.tenantId, productIdentifier, category, 1, now, now);
      st.versionInsert.run(passportId, 1, JSON.stringify(normalized), dataHash, validateNote(note), now, actor);
      appendAudit(st, { actor, action: 'passport.created', target: passportId, details: { version: 1, dataHash } });
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw conflict('A passport with this id or productIdentifier already exists');
    throw err;
  }
  return { id: passportId, version: 1, dataHash };
}

export function addVersion(db, st, { tenant, passport, data, note, expectedVersion }) {
  const normalized = normalizeData(data);
  const dataHash = hashData(normalized);
  const actor = `key:${tenant.keyId}`;
  return tx(db, () => {
    // Re-read inside the transaction so concurrent updates cannot both win.
    const current = st.passportById.get(passport.id);
    if (expectedVersion !== undefined && expectedVersion !== current.current_version) {
      throw conflict(`expectedVersion ${expectedVersion} does not match current version ${current.current_version}`);
    }
    const latest = st.versionGet.get(passport.id, current.current_version);
    if (latest.data_hash === dataHash) return { id: passport.id, version: current.current_version, dataHash, changed: false };
    const version = current.current_version + 1;
    const now = new Date().toISOString();
    st.versionInsert.run(passport.id, version, JSON.stringify(normalized), dataHash, validateNote(note), now, actor);
    st.passportBump.run(version, now, passport.id);
    appendAudit(st, { actor, action: 'passport.updated', target: passport.id, details: { version, dataHash } });
    return { id: passport.id, version, dataHash, changed: true };
  });
}

// ---------------------------------------------------------------- reads

export function ownPassport(st, tenant, id) {
  const p = st.passportById.get(id);
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
 * Snapshot cache for the public read path. Versions are immutable and every
 * change bumps passports.rev, so a cached snapshot is valid as long as the rev
 * matches: one primary-key lookup per request, no JSON parsing, no joins.
 * This stays correct even with several processes sharing the database.
 */
export function createSnapshotCache(st, max = 10_000) {
  const lru = createLru(max);
  return {
    /** Returns {passport, snapshot} or null if the passport does not exist. */
    load(id) {
      const passport = st.passportById.get(id);
      if (!passport) return null;
      let snap = lru.get(id);
      if (!snap || snap.rev !== passport.rev) {
        const v = st.versionGet.get(id, passport.current_version);
        snap = {
          rev: passport.rev,
          version: v.version,
          updatedAt: passport.updated_at,
          dataHash: v.data_hash,
          data: JSON.parse(v.data),
          documents: st.docActive.all(id),
          rendered: new Map(), // per (level, lang, format) prepared bodies
        };
        snap.publicHash = hashData(snap.data.public);
        lru.set(id, snap);
      }
      return { passport, snapshot: snap };
    },
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
