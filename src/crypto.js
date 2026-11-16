import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const sha256 = (input) => createHash('sha256').update(input).digest('hex');

/** High-entropy bearer token. Only its SHA-256 is stored server-side. */
export const newToken = (prefix) => `${prefix}_${randomBytes(32).toString('base64url')}`;

export function safeEqual(a, b) {
  return timingSafeEqual(Buffer.from(sha256(a), 'hex'), Buffer.from(sha256(b), 'hex'));
}

/** Deterministic JSON (sorted keys) so the same data always hashes the same. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(',')}}`;
}
