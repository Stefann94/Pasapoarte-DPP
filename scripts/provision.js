// Sets up the whole production stack through the Supabase and Vercel APIs:
//   1. Supabase project in Frankfurt (reused if it already exists)
//   2. database schema + private storage bucket
//   3. Vercel environment variables + production redeploy
// Results (connection string, keys) are written to .env, never printed.
//
// Needs in .env:  SUPABASE_ACCESS_TOKEN (supabase.com/dashboard/account/tokens)
//                 VERCEL_TOKEN          (vercel.com/account/tokens)
// Usage: npm run provision

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { loadSchema } from '../src/db.js';

const ENV_FILE = new URL('../.env', import.meta.url);
const PROJECT_NAME = process.env.SUPABASE_PROJECT_NAME ?? 'pasapoarte-dpp';
const REGION = 'eu-central-1'; // Frankfurt, next to Vercel fra1
const VERCEL_PROJECT = process.env.VERCEL_PROJECT ?? 'pasapoarte-dpp';
const BUCKET = process.env.STORAGE_BUCKET ?? 'dpp-documents';

// ------------------------------------------------------------------ .env helpers

function readEnvFile() {
  const out = {};
  if (!existsSync(ENV_FILE)) return out;
  for (const line of readFileSync(ENV_FILE, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=(.*)$/.exec(line);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

function saveEnv(updates) {
  let text = existsSync(ENV_FILE) ? readFileSync(ENV_FILE, 'utf8') : '';
  for (const [key, value] of Object.entries(updates)) {
    const re = new RegExp(`^${key}=.*$`, 'm');
    text = re.test(text) ? text.replace(re, `${key}=${value}`) : `${text.replace(/\n*$/, '\n')}${key}=${value}\n`;
  }
  writeFileSync(ENV_FILE, text);
}

const env = { ...readEnvFile(), ...Object.fromEntries(Object.entries(process.env).filter(([, v]) => v)) };
const step = (msg) => console.log(`\n▶ ${msg}`);
const ok = (msg) => console.log(`  ✔ ${msg}`);

if (!env.SUPABASE_ACCESS_TOKEN) throw new Error('SUPABASE_ACCESS_TOKEN missing in .env');
if (!env.VERCEL_TOKEN) throw new Error('VERCEL_TOKEN missing in .env');

async function api(base, token, method, path, body) {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const err = new Error(`${method} ${path} -> ${res.status}: ${typeof data === 'string' ? data : JSON.stringify(data)}`);
    err.status = res.status;
    throw err;
  }
  return data;
}
const supa = (method, path, body) => api('https://api.supabase.com', env.SUPABASE_ACCESS_TOKEN, method, path, body);
const vercel = (method, path, body) => api('https://api.vercel.com', env.VERCEL_TOKEN, method, path, body);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------ 1. Supabase project

step('Supabase project');
let project = (await supa('GET', '/v1/projects')).find((p) => p.name === PROJECT_NAME);
let dbPass = env.SUPABASE_DB_PASSWORD;

if (project) {
  ok(`reusing existing project "${PROJECT_NAME}" (${project.region})`);
  if (!dbPass) {
    throw new Error(
      'Project exists but its database password is unknown. Put it in .env as SUPABASE_DB_PASSWORD ' +
        '(or reset it in Supabase: Project Settings -> Database) and run again.',
    );
  }
} else {
  const orgs = await supa('GET', '/v1/organizations');
  if (!orgs.length) throw new Error('No Supabase organization is visible to this token');
  // Never pick an organization by accident: use SUPABASE_ORG (name or slug),
  // or the only organization the token can see.
  const wanted = env.SUPABASE_ORG?.toLowerCase();
  const org = wanted
    ? orgs.find((o) => o.name.toLowerCase() === wanted || (o.slug ?? o.id).toLowerCase() === wanted)
    : orgs.length === 1
      ? orgs[0]
      : null;
  if (!org) {
    throw new Error(
      `Cannot choose the organization automatically. Set SUPABASE_ORG in .env to one of: ${orgs.map((o) => `"${o.name}"`).join(', ')}`,
    );
  }
  dbPass = randomBytes(24).toString('base64url');
  saveEnv({ SUPABASE_DB_PASSWORD: dbPass }); // saved before creation so it is never lost
  const body = { name: PROJECT_NAME, db_pass: dbPass, region: REGION, organization_slug: org.slug ?? org.id };
  try {
    project = await supa('POST', '/v1/projects', body);
  } catch (err) {
    if (err.status !== 400 && err.status !== 422) throw err;
    delete body.organization_slug;
    project = await supa('POST', '/v1/projects', { ...body, organization_id: org.id });
  }
  ok(`created project "${PROJECT_NAME}" in ${REGION} (organization "${org.name}")`);
}
const ref = project.ref ?? project.id;

process.stdout.write('  … waiting for the project to be ready');
for (let i = 0; ; i++) {
  const p = await supa('GET', `/v1/projects/${ref}`);
  if (p.status === 'ACTIVE_HEALTHY') break;
  if (i > 90) throw new Error(`project still not ready (status ${p.status})`);
  process.stdout.write('.');
  await sleep(5000);
}
console.log('');
ok('project is ready');

// ------------------------------------------------------------------ 2. keys, connection string, schema, bucket

step('Database and storage');
const keys = await supa('GET', `/v1/projects/${ref}/api-keys?reveal=true`);
const serviceKey =
  keys.find((k) => k.name === 'service_role')?.api_key ?? keys.find((k) => k.type === 'secret')?.api_key;
if (!serviceKey) throw new Error('could not read the service_role key');
const supabaseUrl = `https://${ref}.supabase.co`;

let poolerHost = `aws-0-${REGION}.pooler.supabase.com`;
try {
  const pooler = await supa('GET', `/v1/projects/${ref}/config/database/pooler`);
  const tx = (Array.isArray(pooler) ? pooler : [pooler]).find((c) => c.pool_mode === 'transaction') ?? pooler[0];
  if (tx?.db_host) poolerHost = tx.db_host;
} catch {
  /* fall back to the standard pooler host */
}
const databaseUrl = `postgresql://postgres.${ref}:${encodeURIComponent(dbPass)}@${poolerHost}:6543/postgres`;

await supa('POST', `/v1/projects/${ref}/database/query`, { query: await loadSchema() });
ok('schema "dpp" created/updated');

const bucketRes = await fetch(`${supabaseUrl}/storage/v1/bucket`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${serviceKey}`, apikey: serviceKey, 'Content-Type': 'application/json' },
  body: JSON.stringify({ id: BUCKET, name: BUCKET, public: false }),
});
const bucketText = await bucketRes.text();
if (!bucketRes.ok && !/already exists|Duplicate/i.test(bucketText)) {
  throw new Error(`creating bucket failed: ${bucketRes.status} ${bucketText}`);
}
ok(`private storage bucket "${BUCKET}" ready`);

const adminToken = env.ADMIN_TOKEN && env.ADMIN_TOKEN.length >= 24 && !env.ADMIN_TOKEN.startsWith('change-me')
  ? env.ADMIN_TOKEN
  : randomBytes(32).toString('base64url');

saveEnv({
  ADMIN_TOKEN: adminToken,
  DATABASE_URL: databaseUrl,
  SUPABASE_URL: supabaseUrl,
  SUPABASE_SERVICE_ROLE_KEY: serviceKey,
  STORAGE_BUCKET: BUCKET,
});
ok('values saved to .env');

// ------------------------------------------------------------------ 3. Vercel

step('Vercel');
const teams = (await vercel('GET', '/v2/teams').catch(() => ({ teams: [] }))).teams ?? [];
let vProject;
let teamQuery = '';
for (const scope of [null, ...teams.map((t) => t.id)]) {
  const q = scope ? `?teamId=${scope}` : '';
  try {
    vProject = await vercel('GET', `/v9/projects/${VERCEL_PROJECT}${q}`);
    teamQuery = q;
    break;
  } catch (err) {
    if (err.status !== 404 && err.status !== 403) throw err;
  }
}
if (!vProject) throw new Error(`Vercel project "${VERCEL_PROJECT}" not found with this token`);
ok(`found project "${vProject.name}"`);

const prodDomain = `${vProject.name}.vercel.app`;
const vars = {
  ADMIN_TOKEN: adminToken,
  DATABASE_URL: databaseUrl,
  SUPABASE_URL: supabaseUrl,
  SUPABASE_SERVICE_ROLE_KEY: serviceKey,
  STORAGE_BUCKET: BUCKET,
  BASE_URL: env.PUBLIC_BASE_URL || `https://${prodDomain}`,
};
const sep = teamQuery ? '&' : '?';
await vercel(
  'POST',
  `/v10/projects/${vProject.id}/env${teamQuery}${sep}upsert=true`,
  Object.entries(vars).map(([key, value]) => ({
    key,
    value,
    type: 'encrypted',
    target: ['production', 'preview'],
  })),
);
ok(`environment variables set: ${Object.keys(vars).join(', ')}`);

const link = vProject.link ?? {};
const deployment = await vercel('POST', `/v13/deployments${teamQuery}${sep}forceNew=1`, {
  name: vProject.name,
  project: vProject.id,
  target: 'production',
  gitSource: link.repoId
    ? { type: 'github', repoId: link.repoId, ref: link.productionBranch ?? 'main' }
    : { type: 'github', org: 'Stefann94', repo: 'Pasapoarte-DPP', ref: 'main' },
});
process.stdout.write('  … deploying');
for (let i = 0; ; i++) {
  const d = await vercel('GET', `/v13/deployments/${deployment.id}${teamQuery}`);
  if (d.readyState === 'READY') break;
  if (d.readyState === 'ERROR' || d.readyState === 'CANCELED') throw new Error(`deployment ${d.readyState}`);
  if (i > 120) throw new Error('deployment is taking too long');
  process.stdout.write('.');
  await sleep(5000);
}
console.log('');
ok('production deployment ready');

// ------------------------------------------------------------------ 4. check

step('Health check');
const health = await (await fetch(`https://${prodDomain}/healthz`)).text();
console.log(`  https://${prodDomain}/healthz -> ${health}`);
