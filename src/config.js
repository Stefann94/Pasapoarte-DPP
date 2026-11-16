import path from 'node:path';

export function loadConfig(env = process.env) {
  const adminToken = env.ADMIN_TOKEN ?? '';
  if (adminToken.length < 24) {
    throw new Error('ADMIN_TOKEN must be set and at least 24 characters long (see .env.example)');
  }
  const port = Number(env.PORT ?? 3000);
  const baseUrl = (env.BASE_URL ?? `http://localhost:${port}`).replace(/\/+$/, '');
  return {
    port,
    baseUrl,
    dataDir: path.resolve(env.DATA_DIR ?? './data'),
    adminToken,
    trustProxy: env.TRUST_PROXY === '1',
    secureCookies: baseUrl.startsWith('https://'),
    maxJsonBytes: 1024 * 1024,
    maxImportBytes: 200 * 1024 * 1024,
    maxDocumentBytes: Number(env.MAX_DOCUMENT_MB ?? 25) * 1024 * 1024,
    rateLimitPerMinute: Number(env.RATE_LIMIT_PER_MINUTE ?? 600),
    sessionTtlMs: 8 * 60 * 60 * 1000,
  };
}
