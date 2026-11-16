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
      (id, tenant_id, product_identifier, category, current_version, created_at, updated_at, model_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`),
    // Bulk creation (one round trip per table for thousands of batteries).
    passportBulkInsert: q(`INSERT INTO dpp.passports
      (id, tenant_id, product_identifier, category, current_version, created_at, updated_at, model_id)
      SELECT u.id, $3, u.pid, $4, 1, $5, $5, $6 FROM unnest($1::text[], $2::text[]) AS u(id, pid)`),
    versionBulkInsert: q(`INSERT INTO dpp.passport_versions
      (passport_id, version, data, data_hash, note, created_at, created_by)
      SELECT u.id, 1, u.data, u.hash, $4, $5, $6 FROM unnest($1::text[], $2::text[], $3::text[]) AS u(id, data, hash)`),
    passportExistingIdentifiers: q(`SELECT product_identifier FROM dpp.passports
      WHERE tenant_id = $1 AND product_identifier = ANY($2::text[]) LIMIT 50`),
    passportExistingIds: q('SELECT id FROM dpp.passports WHERE id = ANY($1::text[]) LIMIT 50'),
    passportBump: q('UPDATE dpp.passports SET current_version = $1, rev = rev + 1, updated_at = $2 WHERE id = $3'),
    passportTouch: q('UPDATE dpp.passports SET rev = rev + 1, updated_at = $1 WHERE id = $2'),
    passportLockForUpdate: q('SELECT * FROM dpp.passports WHERE id = $1 FOR UPDATE'),
    passportList: q(`SELECT id, product_identifier, category, current_version, created_at, updated_at, model_id
                     FROM dpp.passports WHERE tenant_id = $1 ORDER BY created_at, id LIMIT $2 OFFSET $3`),
    passportListByModel: q(`SELECT id, product_identifier, category, current_version, created_at, updated_at, model_id
                     FROM dpp.passports WHERE model_id = $1 ORDER BY created_at, id LIMIT $2 OFFSET $3`),
    passportCountByModel: q('SELECT COUNT(*)::int AS n FROM dpp.passports WHERE model_id = $1'),
    passportRecent: q(`SELECT p.id, p.product_identifier, p.category, p.current_version, p.updated_at, m.name AS model_name
                     FROM dpp.passports p LEFT JOIN dpp.models m ON m.id = p.model_id
                     WHERE p.tenant_id = $1 ORDER BY p.updated_at DESC LIMIT $2`),
    passportFindByIdentifier: q('SELECT id FROM dpp.passports WHERE tenant_id = $1 AND product_identifier = $2'),
    passportCount: q('SELECT COUNT(*)::int AS n FROM dpp.passports WHERE tenant_id = $1'),
    passportAllForTenant: q('SELECT * FROM dpp.passports WHERE tenant_id = $1 ORDER BY created_at, id'),

    versionInsert: q(`INSERT INTO dpp.passport_versions
      (passport_id, version, data, data_hash, note, created_at, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7)`),
    versionGet: q('SELECT * FROM dpp.passport_versions WHERE passport_id = $1 AND version = $2'),
    versionList: q(`SELECT version, data_hash, note, created_at, created_by
                    FROM dpp.passport_versions WHERE passport_id = $1 ORDER BY version`),
    versionAll: q('SELECT * FROM dpp.passport_versions WHERE passport_id = $1 ORDER BY version'),

    // Public read path: passport + its version + model version + all documents in ONE round trip.
    snapshotLoad: q(`SELECT p.*, v.data, v.data_hash,
        m.rev AS model_rev, m.name AS model_name, mv.version AS model_version, mv.data AS model_data,
        COALESCE((SELECT json_agg(d ORDER BY d.created_at, d.id)::text FROM dpp.documents d
                  WHERE d.removed_at IS NULL
                    AND (d.passport_id = p.id OR (p.model_id IS NOT NULL AND d.model_id = p.model_id))), '[]') AS documents_json
      FROM dpp.passports p
      JOIN dpp.passport_versions v ON v.passport_id = p.id AND v.version = p.current_version
      LEFT JOIN dpp.models m ON m.id = p.model_id
      LEFT JOIN dpp.model_versions mv ON mv.model_id = m.id AND mv.version = m.current_version
      WHERE p.id = $1`),
    passportRev: q(`SELECT p.rev, m.rev AS model_rev FROM dpp.passports p
                    LEFT JOIN dpp.models m ON m.id = p.model_id WHERE p.id = $1`),

    modelInsert: q(`INSERT INTO dpp.models (id, tenant_id, name, category, current_version, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, 1, $5, $5)`),
    modelById: q('SELECT * FROM dpp.models WHERE id = $1'),
    modelLockForUpdate: q('SELECT * FROM dpp.models WHERE id = $1 FOR UPDATE'),
    modelBump: q('UPDATE dpp.models SET current_version = $1, rev = rev + 1, updated_at = $2 WHERE id = $3'),
    modelTouch: q('UPDATE dpp.models SET rev = rev + 1, updated_at = $1 WHERE id = $2'),
    modelList: q(`SELECT m.*, (SELECT COUNT(*)::int FROM dpp.passports p WHERE p.model_id = m.id) AS passport_count
                  FROM dpp.models m WHERE m.tenant_id = $1 ORDER BY m.name`),
    modelAllForTenant: q('SELECT * FROM dpp.models WHERE tenant_id = $1 ORDER BY created_at, id'),
    modelVersionInsert: q(`INSERT INTO dpp.model_versions (model_id, version, data, data_hash, note, created_at, created_by)
                           VALUES ($1, $2, $3, $4, $5, $6, $7)`),
    modelVersionGet: q('SELECT * FROM dpp.model_versions WHERE model_id = $1 AND version = $2'),
    modelVersionAll: q('SELECT * FROM dpp.model_versions WHERE model_id = $1 ORDER BY version'),

    docInsert: q(`INSERT INTO dpp.documents (id, passport_id, model_id, name, content_type, size, sha256, access, created_at, removed_at)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`),
    docActive: q('SELECT * FROM dpp.documents WHERE passport_id = $1 AND removed_at IS NULL ORDER BY created_at, id'),
    docAll: q('SELECT * FROM dpp.documents WHERE passport_id = $1 ORDER BY created_at, id'),
    docGet: q('SELECT * FROM dpp.documents WHERE id = $1 AND passport_id = $2 AND removed_at IS NULL'),
    docRemove: q('UPDATE dpp.documents SET removed_at = $1 WHERE id = $2 AND passport_id = $3 AND removed_at IS NULL'),
    modelDocActive: q('SELECT * FROM dpp.documents WHERE model_id = $1 AND removed_at IS NULL ORDER BY created_at, id'),
    modelDocAll: q('SELECT * FROM dpp.documents WHERE model_id = $1 ORDER BY created_at, id'),
    modelDocGet: q('SELECT * FROM dpp.documents WHERE id = $1 AND model_id = $2 AND removed_at IS NULL'),
    modelDocRemove: q('UPDATE dpp.documents SET removed_at = $1 WHERE id = $2 AND model_id = $3 AND removed_at IS NULL'),
    docForTenant: q(`SELECT d.* FROM dpp.documents d
                     LEFT JOIN dpp.passports p ON p.id = d.passport_id LEFT JOIN dpp.models m ON m.id = d.model_id
                     WHERE d.id = $1 AND d.removed_at IS NULL AND COALESCE(p.tenant_id, m.tenant_id) = $2`),
    // A document visible on a passport: its own, or its model's.
    docForPassport: q(`SELECT d.* FROM dpp.documents d JOIN dpp.passports p ON p.id = $2
                       WHERE d.id = $1 AND d.removed_at IS NULL
                         AND (d.passport_id = p.id OR (p.model_id IS NOT NULL AND d.model_id = p.model_id))`),

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

    userInsert: q(`INSERT INTO dpp.users (id, tenant_id, email, setup_token_hash, setup_expires_at, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6)`),
    userByEmail: q(`SELECT u.*, t.name AS tenant_name, t.status AS tenant_status FROM dpp.users u
                    JOIN dpp.tenants t ON t.id = u.tenant_id WHERE u.email = $1 AND u.disabled_at IS NULL`),
    userBySetupToken: q('SELECT * FROM dpp.users WHERE setup_token_hash = $1 AND setup_expires_at > $2 AND disabled_at IS NULL'),
    userSetPassword: q('UPDATE dpp.users SET password_hash = $1, setup_token_hash = NULL, setup_expires_at = NULL WHERE id = $2'),
    userResetSetup: q('UPDATE dpp.users SET setup_token_hash = $1, setup_expires_at = $2 WHERE id = $3'),
    userById: q('SELECT * FROM dpp.users WHERE id = $1'),
    userList: q(`SELECT id, tenant_id, email, created_at, disabled_at, password_hash IS NOT NULL AS active
                 FROM dpp.users WHERE tenant_id = $1 ORDER BY created_at`),
    portalSessionInsert: q('INSERT INTO dpp.portal_sessions (id_hash, user_id, expires_at) VALUES ($1, $2, $3)'),
    portalSessionUser: q(`SELECT u.id, u.email, t.id AS "tenantId", t.name AS "tenantName", t.status
                          FROM dpp.portal_sessions s JOIN dpp.users u ON u.id = s.user_id JOIN dpp.tenants t ON t.id = u.tenant_id
                          WHERE s.id_hash = $1 AND s.expires_at > $2 AND u.disabled_at IS NULL`),
    portalSessionDelete: q('DELETE FROM dpp.portal_sessions WHERE id_hash = $1'),
    portalSessionDeleteForUser: q('DELETE FROM dpp.portal_sessions WHERE user_id = $1'),
    portalSessionSweep: q('DELETE FROM dpp.portal_sessions WHERE expires_at <= $1'),

    ping: q('SELECT 1 AS ok'),
  };
}

/** Runs fn(st) in a transaction; st is bound to the transaction's connection. */
export const tx = (db, fn) => db.transaction((conn) => fn(statements(conn)));

export const isUniqueViolation = (err) => err?.code === '23505';
