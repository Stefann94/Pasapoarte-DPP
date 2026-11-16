import { createReadStream, existsSync, mkdirSync } from 'node:fs';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { sha256 } from './crypto.js';

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Content-addressed document storage on local disk (data/blobs/ab/abcd...).
 * Identical files are stored once and the address doubles as an integrity check.
 * Swap for S3-compatible object storage in production; the interface stays the same.
 */
export function createBlobStore(dir) {
  mkdirSync(dir, { recursive: true });
  const fileFor = (hash) => {
    if (!HEX64.test(hash)) throw new Error('invalid blob hash');
    return path.join(dir, hash.slice(0, 2), hash);
  };
  return {
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
    /** Reads and verifies the whole blob (used for export/migration). */
    async get(hash) {
      const buf = await readFile(fileFor(hash));
      if (sha256(buf) !== hash) throw new Error(`blob ${hash} failed integrity check`);
      return buf;
    },
    /** Streams the blob without buffering it (used for serving downloads). */
    stream(hash) {
      return createReadStream(fileFor(hash));
    },
  };
}
