import { randomUUID } from 'node:crypto';
import { badRequest, HttpError, isPlainObject } from './http.js';
import { canonicalJson, sha256 } from './crypto.js';
import { canSee, LEVELS } from './auth.js';
import { isUniqueViolation, statements, tx } from './db.js';
import { appendAudit } from './audit.js';
import { createLru } from './lru.js';
import { validateExternalUrl } from './mirror.js';

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

// ---------------------------------------------------------------- merging model + item data

/** Deep merge: values from `over` win; nested objects are merged key by key. */
export function deepMerge(base, over) {
  if (!isPlainObject(base) || !isPlainObject(over)) return over === undefined ? base : over;
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = deepMerge(base[k], v);
  return out;
}

/** Effective passport data = model data overlaid with the battery's own data. */
export function effectiveData(modelData, itemData) {
  if (!modelData) return itemData;
  return {
    public: deepMerge(modelData.public, itemData.public),
    legitimateInterest: deepMerge(modelData.legitimateInterest, itemData.legitimateInterest),
    authorities: deepMerge(modelData.authorities, itemData.authorities),
  };
}

// ---------------------------------------------------------------- writes

const conflict = (message) => new HttpError(409, 'conflict', message);
const EMPTY_DATA = { public: {} };
export const MAX_BULK = 5000;

export async function createPassport(db, { tenant, id, productIdentifier, category, modelId, data, note, externalUrl, urlOptions }) {
  let model = null;
  if (modelId !== undefined && modelId !== null) {
    model = await ownModel(statements(db), tenant, modelId);
    category = model.category;
  }
  validatePassportFields({ id, productIdentifier, category });
  const normalized = normalizeData(data ?? EMPTY_DATA);
  const cleanNote = validateNote(note);
  const external = externalUrl ? validateExternalUrl(externalUrl, urlOptions) : null;
  const passportId = id ?? randomUUID();
  const now = new Date().toISOString();
  const dataHash = hashData(normalized);
  const { actor } = tenant;
  try {
    await tx(db, async (st) => {
      await st.passportInsert.run(passportId, tenant.tenantId, productIdentifier, category, 1, now, now, model?.id ?? null, external);
      await st.versionInsert.run(passportId, 1, JSON.stringify(normalized), dataHash, cleanNote, now, actor);
      await appendAudit(st, { actor, action: 'passport.created', target: passportId, details: { version: 1, dataHash, modelId: model?.id ?? null } });
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw conflict('A passport with this id or productIdentifier already exists');
    throw err;
  }
  return { id: passportId, version: 1, dataHash, modelId: model?.id ?? null, externalUrl: external };
}

/**
 * Creates passports for many batteries of one model in a single transaction
 * (two INSERT statements in total). items: [{productIdentifier, id?, data?}]
 */
export async function createPassportsBulk(db, { tenant, model, items, note, urlOptions }) {
  if (!Array.isArray(items) || !items.length) throw badRequest('items must be a non-empty array');
  if (items.length > MAX_BULK) throw badRequest(`At most ${MAX_BULK} batteries per request`);
  const cleanNote = validateNote(note);
  const seenPid = new Set();
  const seenId = new Set();
  const rows = items.map((item, i) => {
    if (!isPlainObject(item)) throw badRequest(`items[${i}] must be an object`);
    const pid = typeof item.productIdentifier === 'string' ? item.productIdentifier.trim() : item.productIdentifier;
    try {
      validatePassportFields({ id: item.id, productIdentifier: pid, category: model.category });
    } catch (err) {
      throw badRequest(`items[${i}]: ${err.message}`);
    }
    if (seenPid.has(pid)) throw badRequest(`Duplicate productIdentifier in request: ${pid}`);
    seenPid.add(pid);
    const id = item.id ?? randomUUID();
    if (seenId.has(id)) throw badRequest(`Duplicate id in request: ${id}`);
    seenId.add(id);
    const data = normalizeData(item.data ?? EMPTY_DATA);
    let ext = '';
    if (item.externalUrl) {
      try {
        ext = validateExternalUrl(item.externalUrl, urlOptions);
      } catch (err) {
        throw badRequest(`items[${i}]: ${err.message}`);
      }
    }
    return { id, pid, ext, data: JSON.stringify(data), hash: hashData(data) };
  });

  const st = statements(db);
  const existing = await st.passportExistingIdentifiers.all(tenant.tenantId, rows.map((r) => r.pid));
  if (existing.length) {
    throw conflict(`Already registered: ${existing.map((e) => e.product_identifier).slice(0, 20).join(', ')}`);
  }
  const explicitIds = rows.filter((r, i) => items[i].id !== undefined).map((r) => r.id);
  if (explicitIds.length && (await st.passportExistingIds.all(explicitIds)).length) {
    throw conflict('One or more passport ids are already in use');
  }

  const now = new Date().toISOString();
  const { actor } = tenant;
  try {
    await tx(db, async (t) => {
      await t.passportBulkInsert.run(rows.map((r) => r.id), rows.map((r) => r.pid), tenant.tenantId, model.category, now, model.id, rows.map((r) => r.ext));
      await t.versionBulkInsert.run(rows.map((r) => r.id), rows.map((r) => r.data), rows.map((r) => r.hash), cleanNote, now, actor);
      await appendAudit(t, {
        actor,
        action: 'passports.bulk_created',
        target: model.id,
        details: { count: rows.length, first: rows[0].pid, last: rows.at(-1).pid },
      });
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw conflict('Some batteries were registered concurrently; retry the request');
    throw err;
  }
  return rows.map((r) => ({ id: r.id, productIdentifier: r.pid }));
}

export async function addVersion(db, { tenant, passport, data, note, expectedVersion }) {
  const normalized = normalizeData(data ?? EMPTY_DATA);
  const cleanNote = validateNote(note);
  const dataHash = hashData(normalized);
  const { actor } = tenant;
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

export function validateModelName(name) {
  if (typeof name !== 'string' || !name.trim() || name.length > 200) {
    throw badRequest('Model name must be a non-empty string (max 200 characters)');
  }
  return name.trim();
}

export async function createModel(db, { tenant, name, category, data, note }) {
  const cleanName = validateModelName(name);
  if (!CATEGORIES.includes(category)) throw badRequest(`category must be one of: ${CATEGORIES.join(', ')}`);
  const normalized = normalizeData(data ?? EMPTY_DATA);
  const cleanNote = validateNote(note);
  const id = randomUUID();
  const now = new Date().toISOString();
  const dataHash = hashData(normalized);
  const { actor } = tenant;
  try {
    await tx(db, async (st) => {
      await st.modelInsert.run(id, tenant.tenantId, cleanName, category, now);
      await st.modelVersionInsert.run(id, 1, JSON.stringify(normalized), dataHash, cleanNote, now, actor);
      await appendAudit(st, { actor, action: 'model.created', target: id, details: { name: cleanName, version: 1, dataHash } });
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw conflict('A model with this name already exists');
    throw err;
  }
  return { id, name: cleanName, category, version: 1, dataHash };
}

/** New model version: every passport of the model shows it immediately. */
export async function addModelVersion(db, { tenant, model, data, note, expectedVersion }) {
  const normalized = normalizeData(data ?? EMPTY_DATA);
  const cleanNote = validateNote(note);
  const dataHash = hashData(normalized);
  const { actor } = tenant;
  return tx(db, async (st) => {
    const current = await st.modelLockForUpdate.get(model.id);
    if (expectedVersion !== undefined && expectedVersion !== current.current_version) {
      throw conflict(`expectedVersion ${expectedVersion} does not match current version ${current.current_version}`);
    }
    const latest = await st.modelVersionGet.get(model.id, current.current_version);
    if (latest.data_hash === dataHash) return { id: model.id, version: current.current_version, dataHash, changed: false };
    const version = current.current_version + 1;
    const now = new Date().toISOString();
    await st.modelVersionInsert.run(model.id, version, JSON.stringify(normalized), dataHash, cleanNote, now, actor);
    await st.modelBump.run(version, now, model.id);
    await appendAudit(st, { actor, action: 'model.updated', target: model.id, details: { version, dataHash } });
    return { id: model.id, version, dataHash, changed: true };
  });
}

// ---------------------------------------------------------------- reads

export async function ownPassport(st, tenant, id) {
  const p = await st.passportById.get(id);
  if (!p || p.tenant_id !== tenant.tenantId) throw new HttpError(404, 'passport_not_found', 'Passport not found');
  return p;
}

export async function ownModel(st, tenant, id) {
  const m = typeof id === 'string' ? await st.modelById.get(id) : null;
  if (!m || m.tenant_id !== tenant.tenantId) throw new HttpError(404, 'model_not_found', 'Model not found');
  return m;
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
  scope: d.model_id ? 'model' : 'passport',
  createdAt: d.created_at,
  url: passportId ? documentUrl(config, passportId, d.id) : null,
});

/**
 * Snapshot cache for the public read path (QR scans).
 *  - A miss loads passport + model + documents in ONE query.
 *  - A hit younger than ttlMs is served with zero database round trips.
 *  - An older hit costs one tiny lookup (passport rev + model rev). Versions
 *    are immutable and every change bumps a rev, so this is always correct,
 *    also with several server instances sharing the database.
 *  - Writes on this instance call invalidate() / invalidateAll().
 * Each snapshot also stores its rendered, compressed responses.
 */
export function createSnapshotCache(st, { max = 10_000, ttlMs = 2000 } = {}) {
  let lru = createLru(max);

  async function fetchFresh(id) {
    const row = await st.snapshotLoad.get(id);
    if (!row) return null;
    const { data, data_hash, documents_json, model_rev, model_name, model_version, model_data, ...passport } = row;
    const itemData = JSON.parse(data);
    const merged = effectiveData(model_data ? JSON.parse(model_data) : null, itemData);
    const snap = {
      passport,
      rev: passport.rev,
      modelRev: model_rev ?? null,
      model: passport.model_id ? { id: passport.model_id, name: model_name, version: model_version } : null,
      version: passport.current_version,
      updatedAt: passport.updated_at,
      dataHash: data_hash,
      data: merged,
      publicHash: hashData(merged.public),
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
        if (row.rev === snap.rev && (row.model_rev ?? null) === snap.modelRev) snap.checkedAt = Date.now();
        else snap = null;
      }
      snap ??= await fetchFresh(id);
      return snap ? { passport: snap.passport, snapshot: snap } : null;
    },
    invalidate: (id) => lru.delete(id),
    /** A model change affects many passports: drop everything (cheap, rebuilt on demand). */
    invalidateAll: () => {
      lru = createLru(max);
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
    model: snap.model ? { name: snap.model.name, version: snap.model.version } : null,
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
