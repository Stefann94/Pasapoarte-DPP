// One-time (and repeatable) setup of a Supabase project:
//   1. creates/updates the database schema (schema "dpp")
//   2. creates the private storage bucket for documents
// Usage: put DATABASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY in .env, then: npm run migrate

import pg from 'pg';
import { loadSchema } from '../src/db.js';

const { DATABASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, STORAGE_BUCKET = 'dpp-documents', DATABASE_CA_CERT } = process.env;
if (!DATABASE_URL) throw new Error('DATABASE_URL is not set');

const url = new URL(DATABASE_URL);
url.searchParams.delete('sslmode');
const isLocal = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
const client = new pg.Client({
  connectionString: url.toString(),
  ssl: isLocal ? false : DATABASE_CA_CERT ? { ca: DATABASE_CA_CERT } : { rejectUnauthorized: false },
});
await client.connect();
await client.query(await loadSchema());
const { rows } = await client.query(
  "SELECT table_name FROM information_schema.tables WHERE table_schema = 'dpp' ORDER BY table_name",
);
await client.end();
console.log(`Database schema OK: ${rows.map((r) => r.table_name).join(', ')}`);

if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
  const res = await fetch(`${SUPABASE_URL.replace(/\/+$/, '')}/storage/v1/bucket`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ id: STORAGE_BUCKET, name: STORAGE_BUCKET, public: false }),
  });
  const body = await res.text();
  if (res.ok) console.log(`Storage bucket "${STORAGE_BUCKET}" created (private)`);
  else if (/already exists|Duplicate/i.test(body)) console.log(`Storage bucket "${STORAGE_BUCKET}" already exists`);
  else throw new Error(`Creating storage bucket failed: ${res.status} ${body}`);
} else {
  console.log('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set: skipped storage bucket');
}
