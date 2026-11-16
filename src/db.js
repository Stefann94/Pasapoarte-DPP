import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS tenants (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  vat_id     TEXT,
  status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL REFERENCES tenants(id),
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

-- rev increases on every change (new version, document added/removed) and is
-- used as the cache key for rendered public pages.
CREATE TABLE IF NOT EXISTS passports (
  id                 TEXT PRIMARY KEY,
  tenant_id          TEXT NOT NULL REFERENCES tenants(id),
  product_identifier TEXT NOT NULL,
  category           TEXT NOT NULL,
  current_version    INTEGER NOT NULL,
  rev                INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  UNIQUE (tenant_id, product_identifier)
);
CREATE INDEX IF NOT EXISTS passports_tenant ON passports(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS passport_versions (
  passport_id TEXT NOT NULL REFERENCES passports(id),
  version     INTEGER NOT NULL,
  data        TEXT NOT NULL,
  data_hash   TEXT NOT NULL,
  note        TEXT,
  created_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  PRIMARY KEY (passport_id, version)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS documents (
  id           TEXT PRIMARY KEY,
  passport_id  TEXT NOT NULL REFERENCES passports(id),
  name         TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size         INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  access       TEXT NOT NULL CHECK (access IN ('public', 'legitimate_interest', 'authority')),
  created_at   TEXT NOT NULL,
  removed_at   TEXT
);
CREATE INDEX IF NOT EXISTS documents_passport ON documents(passport_id);

CREATE TABLE IF NOT EXISTS accessors (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL CHECK (role IN ('legitimate_interest', 'authority')),
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash     TEXT PRIMARY KEY,
  accessor_id TEXT NOT NULL REFERENCES accessors(id),
  expires_at  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS audit_log (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  target    TEXT,
  details   TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS versions_no_update BEFORE UPDATE ON passport_versions
BEGIN SELECT RAISE(ABORT, 'passport versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS versions_no_delete BEFORE DELETE ON passport_versions
BEGIN SELECT RAISE(ABORT, 'passport versions are immutable'); END;
`;

export function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA cache_size = -65536;
    PRAGMA temp_store = MEMORY;
  `);
  db.exec(SCHEMA);
  return db;
}

/**
 * Prepares every statement once. Re-preparing per request is the main
 * avoidable cost with SQLite, so all queries go through this object.
 */
export function prepareStatements(db) {
  const q = (sql) => db.prepare(sql);
  return {
    tenantInsert: q('INSERT INTO tenants (id, name, vat_id, created_at) VALUES (?, ?, ?, ?)'),
    tenantById: q('SELECT * FROM tenants WHERE id = ?'),
    tenantList: q('SELECT * FROM tenants ORDER BY created_at'),
    tenantSetStatus: q('UPDATE tenants SET status = ? WHERE id = ?'),

    apiKeyInsert: q('INSERT INTO api_keys (id, tenant_id, token_hash, created_at) VALUES (?, ?, ?, ?)'),
    apiKeyRevoke: q('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL'),
    apiKeyAuth: q(`SELECT k.id AS keyId, t.id AS tenantId, t.name AS tenantName, t.status
                   FROM api_keys k JOIN tenants t ON t.id = k.tenant_id
                   WHERE k.token_hash = ? AND k.revoked_at IS NULL`),

    passportById: q('SELECT * FROM passports WHERE id = ?'),
    passportInsert: q(`INSERT INTO passports
      (id, tenant_id, product_identifier, category, current_version, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`),
    passportBump: q('UPDATE passports SET current_version = ?, rev = rev + 1, updated_at = ? WHERE id = ?'),
    passportTouch: q('UPDATE passports SET rev = rev + 1, updated_at = ? WHERE id = ?'),
    passportList: q(`SELECT id, product_identifier, category, current_version, created_at, updated_at
                     FROM passports WHERE tenant_id = ? ORDER BY created_at, id LIMIT ? OFFSET ?`),
    passportCount: q('SELECT COUNT(*) AS n FROM passports WHERE tenant_id = ?'),
    passportAllForTenant: q('SELECT * FROM passports WHERE tenant_id = ? ORDER BY created_at, id'),

    versionInsert: q(`INSERT INTO passport_versions
      (passport_id, version, data, data_hash, note, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`),
    versionGet: q('SELECT * FROM passport_versions WHERE passport_id = ? AND version = ?'),
    versionList: q(`SELECT version, data_hash, note, created_at, created_by
                    FROM passport_versions WHERE passport_id = ? ORDER BY version`),
    versionAll: q('SELECT * FROM passport_versions WHERE passport_id = ? ORDER BY version'),

    docInsert: q(`INSERT INTO documents (id, passport_id, name, content_type, size, sha256, access, created_at, removed_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    docActive: q('SELECT * FROM documents WHERE passport_id = ? AND removed_at IS NULL ORDER BY created_at, id'),
    docAll: q('SELECT * FROM documents WHERE passport_id = ? ORDER BY created_at, id'),
    docGet: q('SELECT * FROM documents WHERE id = ? AND passport_id = ? AND removed_at IS NULL'),
    docRemove: q('UPDATE documents SET removed_at = ? WHERE id = ? AND passport_id = ? AND removed_at IS NULL'),

    accessorInsert: q('INSERT INTO accessors (id, name, role, token_hash, created_at) VALUES (?, ?, ?, ?, ?)'),
    accessorList: q('SELECT id, name, role, created_at, revoked_at FROM accessors ORDER BY created_at'),
    accessorRevoke: q('UPDATE accessors SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL'),
    accessorByToken: q('SELECT id, name, role FROM accessors WHERE token_hash = ? AND revoked_at IS NULL'),

    sessionInsert: q('INSERT INTO sessions (id_hash, accessor_id, expires_at) VALUES (?, ?, ?)'),
    sessionAccessor: q(`SELECT a.id, a.name, a.role FROM sessions s JOIN accessors a ON a.id = s.accessor_id
                        WHERE s.id_hash = ? AND s.expires_at > ? AND a.revoked_at IS NULL`),
    sessionDelete: q('DELETE FROM sessions WHERE id_hash = ?'),
    sessionDeleteForAccessor: q('DELETE FROM sessions WHERE accessor_id = ?'),
    sessionSweep: q('DELETE FROM sessions WHERE expires_at <= ?'),

    auditLast: q('SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1'),
    auditInsert: q(`INSERT INTO audit_log (ts, actor, action, target, details, prev_hash, hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)`),
    auditRecent: q('SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?'),
    auditAll: q('SELECT * FROM audit_log ORDER BY seq'),
  };
}

/** Runs fn inside a write transaction. node:sqlite is synchronous, so fn must be too. */
export function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export const isUniqueViolation = (err) => /UNIQUE constraint failed|PRIMARY KEY/.test(err?.message ?? '');
