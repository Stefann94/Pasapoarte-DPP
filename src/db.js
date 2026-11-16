import { readFile } from 'node:fs/promises';
import pg from 'pg';

/*
 * One small interface over two drivers:
 *   - production: PostgreSQL via `pg` (Supabase, through its connection pooler)
 *   - local dev & tests: PGlite (real Postgres compiled to WASM, in-process)
 * Both expose { query(sql, params) -> {rows, rowCount}, transaction(fn), exec(sql), close() }.
 */

export async function openDatabase(config) {
  return config.databaseUrl ? openPostgres(config) : openPglite(config);
}

function openPostgres(config) {
  const url = new URL(config.databaseUrl);
  url.searchParams.delete('sslmode'); // SSL is configured explicitly below
  const isLocal = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
  const pool = new pg.Pool({
    connectionString: url.toString(),
    ssl: isLocal ? false : config.databaseCa ? { ca: config.databaseCa } : { rejectUnauthorized: false },
    max: config.dbPoolSize,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000,
  });
  pool.on('error', (err) => console.error('postgres pool error', err));
  const wrap = (client) => ({
    async query(sql, params) {
      const r = await client.query(sql, params);
      return { rows: r.rows, rowCount: r.rowCount ?? 0 };
    },
  });
  return {
    kind: 'postgres',
    ...wrap(pool),
    async transaction(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(wrap(client));
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
    exec: (sql) => pool.query(sql),
    close: () => pool.end(),
  };
}

async function openPglite(config) {
  const { PGlite } = await import('@electric-sql/pglite');
  const db = await PGlite.create(config.pgliteDir);
  const wrap = (client) => ({
    async query(sql, params) {
      const r = await client.query(sql, params);
      return { rows: r.rows, rowCount: r.affectedRows ?? 0 };
    },
  });
  // A local database is created on the fly; Supabase is migrated with `npm run migrate`.
  await db.exec(await loadSchema());
  return {
    kind: 'pglite',
    ...wrap(db),
    transaction: (fn) => db.transaction((tx) => fn(wrap(tx))),
    exec: (sql) => db.exec(sql),
    close: () => db.close(),
  };
}

export const loadSchema = () => readFile(new URL('./schema.sql', import.meta.url), 'utf8');

/**
 * All SQL in one place. `conn` is the pool or a transaction client, so the same
 * statements work inside and outside transactions.
 */
export function statements(conn) {
  const q = (sql) => ({
    get: async (...p) => (await conn.query(sql, p)).rows[0],
    all: async (...p) => (await conn.query(sql, p)).rows,
    run: async (...p) => ({ changes: (await conn.query(sql, p)).rowCount }),
  });
  return {
    tenantInsert: q('INSERT INTO dpp.tenants (id, name, vat_id, created_at) VALUES ($1, $2, $3, $4)'),
    tenantById: q('SELECT * FROM dpp.tenants WHERE id = $1'),
    tenantList: q('SELECT * FROM dpp.tenants ORDER BY created_at'),
    tenantSetStatus: q('UPDATE dpp.tenants SET status = $1 WHERE id = $2'),

    apiKeyInsert: q('INSERT INTO dpp.api_keys (id, tenant_id, token_hash, created_at) VALUES ($1, $2, $3, $4)'),
    apiKeyRevoke: q('UPDATE dpp.api_keys SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL'),
    apiKeyAuth: q(`SELECT k.id AS "keyId", t.id AS "tenantId", t.name AS "tenantName", t.status
                   FROM dpp.api_keys k JOIN dpp.tenants t ON t.id = k.tenant_id
                   WHERE k.token_hash = $1 AND k.revoked_at IS NULL`),

    passportById: q('SELECT * FROM dpp.passports WHERE id = $1'),
    passportInsert: q(`INSERT INTO dpp.passports
      (id, tenant_id, product_identifier, category, current_version, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)`),
    passportBump: q('UPDATE dpp.passports SET current_version = $1, rev = rev + 1, updated_at = $2 WHERE id = $3'),
    passportTouch: q('UPDATE dpp.passports SET rev = rev + 1, updated_at = $1 WHERE id = $2'),
    passportLockForUpdate: q('SELECT * FROM dpp.passports WHERE id = $1 FOR UPDATE'),
    passportList: q(`SELECT id, product_identifier, category, current_version, created_at, updated_at
                     FROM dpp.passports WHERE tenant_id = $1 ORDER BY created_at, id LIMIT $2 OFFSET $3`),
    passportCount: q('SELECT COUNT(*)::int AS n FROM dpp.passports WHERE tenant_id = $1'),
    passportAllForTenant: q('SELECT * FROM dpp.passports WHERE tenant_id = $1 ORDER BY created_at, id'),

    versionInsert: q(`INSERT INTO dpp.passport_versions
      (passport_id, version, data, data_hash, note, created_at, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7)`),
    versionGet: q('SELECT * FROM dpp.passport_versions WHERE passport_id = $1 AND version = $2'),
    versionList: q(`SELECT version, data_hash, note, created_at, created_by
                    FROM dpp.passport_versions WHERE passport_id = $1 ORDER BY version`),
    versionAll: q('SELECT * FROM dpp.passport_versions WHERE passport_id = $1 ORDER BY version'),

    // Public read path: passport + current version + active documents in ONE round trip.
    snapshotLoad: q(`SELECT p.*, v.data, v.data_hash,
        COALESCE((SELECT json_agg(d ORDER BY d.created_at, d.id)::text FROM dpp.documents d
                  WHERE d.passport_id = p.id AND d.removed_at IS NULL), '[]') AS documents_json
      FROM dpp.passports p
      JOIN dpp.passport_versions v ON v.passport_id = p.id AND v.version = p.current_version
      WHERE p.id = $1`),
    passportRev: q('SELECT rev FROM dpp.passports WHERE id = $1'),

    docInsert: q(`INSERT INTO dpp.documents (id, passport_id, name, content_type, size, sha256, access, created_at, removed_at)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`),
    docActive: q('SELECT * FROM dpp.documents WHERE passport_id = $1 AND removed_at IS NULL ORDER BY created_at, id'),
    docAll: q('SELECT * FROM dpp.documents WHERE passport_id = $1 ORDER BY created_at, id'),
    docGet: q('SELECT * FROM dpp.documents WHERE id = $1 AND passport_id = $2 AND removed_at IS NULL'),
    docRemove: q('UPDATE dpp.documents SET removed_at = $1 WHERE id = $2 AND passport_id = $3 AND removed_at IS NULL'),

    accessorInsert: q('INSERT INTO dpp.accessors (id, name, role, token_hash, created_at) VALUES ($1, $2, $3, $4, $5)'),
    accessorList: q('SELECT id, name, role, created_at, revoked_at FROM dpp.accessors ORDER BY created_at'),
    accessorRevoke: q('UPDATE dpp.accessors SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL'),
    accessorByToken: q('SELECT id, name, role FROM dpp.accessors WHERE token_hash = $1 AND revoked_at IS NULL'),

    sessionInsert: q('INSERT INTO dpp.sessions (id_hash, accessor_id, expires_at) VALUES ($1, $2, $3)'),
    sessionAccessor: q(`SELECT a.id, a.name, a.role FROM dpp.sessions s JOIN dpp.accessors a ON a.id = s.accessor_id
                        WHERE s.id_hash = $1 AND s.expires_at > $2 AND a.revoked_at IS NULL`),
    sessionDelete: q('DELETE FROM dpp.sessions WHERE id_hash = $1'),
    sessionDeleteForAccessor: q('DELETE FROM dpp.sessions WHERE accessor_id = $1'),
    sessionSweep: q('DELETE FROM dpp.sessions WHERE expires_at <= $1'),

    // Serialises audit appends across concurrent transactions/instances so the hash chain never forks.
    auditLock: q('SELECT pg_advisory_xact_lock(727274) AS locked'),
    auditLast: q('SELECT hash FROM dpp.audit_log ORDER BY seq DESC LIMIT 1'),
    auditInsert: q(`INSERT INTO dpp.audit_log (ts, actor, action, target, details, prev_hash, hash)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)`),
    auditRecent: q('SELECT * FROM dpp.audit_log ORDER BY seq DESC LIMIT $1'),
    auditAll: q('SELECT * FROM dpp.audit_log ORDER BY seq'),

    ping: q('SELECT 1 AS ok'),
  };
}

/** Runs fn(st) in a transaction; st is bound to the transaction's connection. */
export const tx = (db, fn) => db.transaction((conn) => fn(statements(conn)));

export const isUniqueViolation = (err) => err?.code === '23505';
