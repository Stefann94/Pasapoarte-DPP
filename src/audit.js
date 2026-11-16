import { canonicalJson, sha256 } from './crypto.js';

const entryHash = (e) =>
  sha256(canonicalJson({ ts: e.ts, actor: e.actor, action: e.action, target: e.target, details: e.details, prev: e.prev_hash }));

/**
 * Append-only, hash-chained audit log. Each entry commits to the previous one,
 * so editing or removing a past entry breaks verification. For stronger
 * guarantees, periodically publish the latest hash outside this database.
 */
export function appendAudit(st, { actor, action, target = null, details = {} }) {
  const prev_hash = st.auditLast.get()?.hash ?? 'GENESIS';
  const entry = { ts: new Date().toISOString(), actor, action, target, details: canonicalJson(details), prev_hash };
  st.auditInsert.run(entry.ts, actor, action, target, entry.details, prev_hash, entryHash(entry));
}

export function verifyAudit(st) {
  let prev = 'GENESIS';
  let count = 0;
  for (const row of st.auditAll.iterate()) {
    if (row.prev_hash !== prev || entryHash(row) !== row.hash) {
      return { ok: false, entries: count, brokenAtSeq: row.seq };
    }
    prev = row.hash;
    count++;
  }
  return { ok: true, entries: count, head: prev };
}
