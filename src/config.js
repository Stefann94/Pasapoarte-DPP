import path from 'node:path';

export function loadConfig(env = process.env) {
  const adminToken = env.ADMIN_TOKEN ?? '';
  if (adminToken.length < 24) {
    throw new Error('ADMIN_TOKEN must be set and at least 24 characters long (see .env.example)');
  }
  const port = Number(env.PORT ?? 3000);
  const vercelUrl = env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${env.VERCEL_PROJECT_PRODUCTION_URL}` : null;
  const baseUrl = (env.BASE_URL ?? vercelUrl ?? `http://localhost:${port}`).replace(/\/+$/, '');
  const dataDir = path.resolve(env.DATA_DIR ?? './data');
  const onVercel = Boolean(env.VERCEL);

  if (onVercel && !env.DATABASE_URL) {
    throw new Error('DATABASE_URL must be set on Vercel (the filesystem there is not persistent)');
  }
  if (onVercel && !env.SUPABASE_URL) {
    throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set on Vercel for document storage');
  }
  if (env.SUPABASE_URL && !env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error('SUPABASE_SERVICE_ROLE_KEY must be set together with SUPABASE_URL');
  }

  return {
    port,
    baseUrl,
    dataDir,
    adminToken,
    // Database: Supabase/Postgres when DATABASE_URL is set, otherwise a local PGlite database.
    databaseUrl: env.DATABASE_URL || null,
    databaseCa: env.DATABASE_CA_CERT || null,
    dbPoolSize: Number(env.DB_POOL_SIZE ?? (onVercel ? 3 : 10)),
    pgliteDir: env.PGLITE_DIR ?? path.join(dataDir, 'pg'),
    // Documents: Supabase Storage when SUPABASE_URL is set, otherwise local disk.
    supabaseUrl: env.SUPABASE_URL || null,
    supabaseServiceKey: env.SUPABASE_SERVICE_ROLE_KEY || null,
    storageBucket: env.STORAGE_BUCKET ?? 'dpp-documents',
    trustProxy: onVercel || env.TRUST_PROXY === '1',
    secureCookies: baseUrl.startsWith('https://'),
    maxJsonBytes: 1024 * 1024,
    // Vercel functions accept request bodies up to 4.5 MB.
    maxImportBytes: (onVercel ? 4 : 200) * 1024 * 1024,
    maxDocumentBytes: Number(env.MAX_DOCUMENT_MB ?? (onVercel ? 4 : 25)) * 1024 * 1024,
    rateLimitPerMinute: Number(env.RATE_LIMIT_PER_MINUTE ?? 600),
    sessionTtlMs: 8 * 60 * 60 * 1000,
    // How long a cached public passport is served without re-checking the
    // database. Writes on the same instance invalidate immediately.
    snapshotTtlMs: Number(env.SNAPSHOT_TTL_MS ?? 2000),
    // Secret Vercel Cron sends as a bearer token (optional, see /api/cron/mirror).
    cronSecret: env.CRON_SECRET || null,
    // Tests only: lets the mirror fetch from localhost over http.
    mirrorAllowPrivate: env.MIRROR_ALLOW_PRIVATE === '1',
  };
}
