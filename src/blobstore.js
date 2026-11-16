import { createReadStream, existsSync, mkdirSync } from 'node:fs';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import path from 'node:path';
import { sha256 } from './crypto.js';

const HEX64 = /^[0-9a-f]{64}$/;
const keyFor = (hash) => {
  if (!HEX64.test(hash)) throw new Error('invalid blob hash');
  return `${hash.slice(0, 2)}/${hash}`;
};

/*
 * Content-addressed document storage: a file is stored under its SHA-256, so
 * identical files are stored once and the address doubles as an integrity
 * check. Interface: put(buf) -> hash, get(hash) -> verified Buffer,
 * open(hash) -> Readable stream for serving.
 */
export function createBlobStore(config) {
  return config.supabaseUrl ? supabaseStore(config) : localStore(path.join(config.dataDir, 'blobs'));
}

function localStore(dir) {
  mkdirSync(dir, { recursive: true });
  const fileFor = (hash) => path.join(dir, ...keyFor(hash).split('/'));
  return {
    kind: 'local',
    async put(buf) {
      const hash = sha256(buf);
      const file = fileFor(hash);
      if (!existsSync(file)) {
        await mkdir(path.dirname(file), { recursive: true });
        const tmp = `${file}.${randomUUID()}.tmp`;
        await writeFile(tmp, buf);
        await rename(tmp, file);
      }
      return hash;
    },
    async get(hash) {
      const buf = await readFile(fileFor(hash));
      if (sha256(buf) !== hash) throw new Error(`blob ${hash} failed integrity check`);
      return buf;
    },
    async open(hash) {
      return createReadStream(fileFor(hash));
    },
  };
}

/** Supabase Storage (private bucket) over its REST API, with the service-role key. */
function supabaseStore({ supabaseUrl, supabaseServiceKey, storageBucket }) {
  const base = `${supabaseUrl.replace(/\/+$/, '')}/storage/v1/object/${encodeURIComponent(storageBucket)}`;
  const auth = { Authorization: `Bearer ${supabaseServiceKey}`, apikey: supabaseServiceKey };
  const fetchObject = async (hash) => {
    const res = await fetch(`${base}/${keyFor(hash)}`, { headers: auth });
    if (!res.ok) throw new Error(`storage download ${hash} failed: ${res.status}`);
    return res;
  };
  return {
    kind: 'supabase',
    async put(buf) {
      const hash = sha256(buf);
      const res = await fetch(`${base}/${keyFor(hash)}`, {
        method: 'POST',
        headers: { ...auth, 'Content-Type': 'application/octet-stream', 'x-upsert': 'true', 'Cache-Control': 'max-age=31536000' },
        body: buf,
      });
      if (!res.ok) throw new Error(`storage upload failed: ${res.status} ${await res.text()}`);
      return hash;
    },
    async get(hash) {
      const buf = Buffer.from(await (await fetchObject(hash)).arrayBuffer());
      if (sha256(buf) !== hash) throw new Error(`blob ${hash} failed integrity check`);
      return buf;
    },
    async open(hash) {
      return Readable.fromWeb((await fetchObject(hash)).body);
    },
  };
}
