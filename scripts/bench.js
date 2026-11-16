// Measures throughput/latency of the public passport page (the QR-scan path).
// Starts its own temporary instance, so no running server is needed.
// Usage: node scripts/bench.js [seconds=5] [concurrency=50]

import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const seconds = Number(process.argv[2] ?? 5);
const concurrency = Number(process.argv[3] ?? 50);
const ADMIN = 'bench-admin-token-0123456789abcdef';

const dataDir = mkdtempSync(path.join(os.tmpdir(), 'dpp-bench-'));
const app = createApp(loadConfig({ ADMIN_TOKEN: ADMIN, DATA_DIR: dataDir, RATE_LIMIT_PER_MINUTE: '100000000' }));
await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${app.server.address().port}`;

const post = async (p, token, body) =>
  (await fetch(base + p, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();

const { apiKey } = await post('/admin/tenants', ADMIN, { name: 'Bench' });
const ids = [];
for (let i = 0; i < 200; i++) {
  const p = await post('/api/passports', apiKey.token, {
    productIdentifier: `B-${i}`,
    category: 'ev',
    data: { public: { model: 'X', capacityKWh: 75, cells: Array.from({ length: 20 }, (_, j) => ({ cell: j, chemistry: 'NMC811' })) } },
  });
  ids.push(p.id);
}

async function run(label, headers) {
  const latencies = [];
  const end = Date.now() + seconds * 1000;
  let n = 0;
  await Promise.all(
    Array.from({ length: concurrency }, async () => {
      while (Date.now() < end) {
        const id = ids[n++ % ids.length];
        const t0 = performance.now();
        const res = await fetch(`${base}/p/${id}?lang=ro`, { headers });
        await res.arrayBuffer();
        latencies.push(performance.now() - t0);
      }
    }),
  );
  latencies.sort((x, y) => x - y);
  const pct = (q) => latencies[Math.floor(latencies.length * q)].toFixed(2);
  console.log(
    `${label.padEnd(28)} ${(latencies.length / seconds).toFixed(0).padStart(7)} req/s   p50 ${pct(0.5)} ms   p99 ${pct(0.99)} ms`,
  );
}

console.log(`${seconds}s per scenario, ${concurrency} concurrent connections, 200 passports\n`);
await run('HTML, brotli', { 'Accept-Encoding': 'br' });
await run('JSON, gzip', { 'Accept-Encoding': 'gzip', Accept: 'application/json' });

app.close();
rmSync(dataDir, { recursive: true, force: true });
