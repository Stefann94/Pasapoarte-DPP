import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const ADMIN = 'test-admin-token-0123456789abcdef';
const PDF = Buffer.from('%PDF-1.4\n% test document\n%%EOF\n');

async function startInstance() {
  const dataDir = mkdtempSync(path.join(os.tmpdir(), 'dpp-test-'));
  const config = loadConfig({ ADMIN_TOKEN: ADMIN, DATA_DIR: dataDir, PGLITE_DIR: 'memory://', BASE_URL: 'https://passport.example.test' });
  const app = await createApp(config);
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const call = async (method, p, { token, json, body, headers = {} } = {}) => {
    const h = { ...headers };
    if (token) h.Authorization = `Bearer ${token}`;
    if (json !== undefined) h['Content-Type'] = 'application/json';
    const res = await fetch(base + p, { method, headers: h, body: json !== undefined ? JSON.stringify(json) : body, redirect: 'manual' });
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {}
    return { status: res.status, headers: res.headers, text, data };
  };
  return {
    app,
    call,
    async stop() {
      await app.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

const sampleData = (capacity = '50 kWh') => ({
  public: {
    manufacturer: { name: 'Acme Cells <script>alert(1)</script>', country: 'RO' },
    batteryModel: 'ACM-50',
    ratedCapacity: capacity,
    chemistry: 'LFP',
    declarationOfConformity: 'https://acme.example/doc.pdf',
  },
  legitimateInterest: { dismantlingInformation: 'Remove 12 bolts on the casing' },
  authorities: { testReports: ['TR-001', 'TR-002'] },
});

describe('DPP hosting', () => {
  let a;
  let b; // second instance, to test migration between providers
  let key;
  let legitToken;
  let authorityToken;
  let tenantId;
  let passportId;
  let restrictedDocUrl;

  before(async () => {
    a = await startInstance();
    b = await startInstance();
  });
  after(async () => {
    await a.stop();
    await b.stop();
  });

  test('admin endpoints require the admin token', async () => {
    assert.equal((await a.call('GET', '/admin/tenants')).status, 401);
    assert.equal((await a.call('GET', '/admin/tenants', { token: 'wrong' })).status, 401);
  });

  test('admin onboards a client and two restricted-access organisations', async () => {
    const t = await a.call('POST', '/admin/tenants', { token: ADMIN, json: { name: 'Importer SRL', vatId: 'RO123' } });
    assert.equal(t.status, 201);
    key = t.data.apiKey.token;
    tenantId = t.data.tenant.id;
    assert.match(key, /^dpk_/);

    const l = await a.call('POST', '/admin/accessors', { token: ADMIN, json: { name: 'Recycler SA', role: 'legitimate_interest' } });
    const au = await a.call('POST', '/admin/accessors', { token: ADMIN, json: { name: 'Market Surveillance', role: 'authority' } });
    legitToken = l.data.token;
    authorityToken = au.data.token;
    assert.match(authorityToken, /^dpa_/);
  });

  test('client creates a passport; validation errors are clear', async () => {
    assert.equal((await a.call('POST', '/api/passports', { json: {} })).status, 401);
    const bad = await a.call('POST', '/api/passports', { token: key, json: { productIdentifier: 'X', category: 'phone', data: { public: {} } } });
    assert.equal(bad.status, 400);
    assert.match(bad.data.message, /category/);
    const unknown = await a.call('POST', '/api/passports', { token: key, json: { productIdentifier: 'X', category: 'ev', data: { public: {}, secret: {} } } });
    assert.equal(unknown.status, 400);

    const r = await a.call('POST', '/api/passports', {
      token: key,
      json: { productIdentifier: 'BAT-0001', category: 'industrial', data: sampleData(), note: 'initial' },
    });
    assert.equal(r.status, 201);
    assert.equal(r.data.version, 1);
    passportId = r.data.id;
    assert.equal(r.data.url, `https://passport.example.test/p/${passportId}`);

    const dup = await a.call('POST', '/api/passports', { token: key, json: { productIdentifier: 'BAT-0001', category: 'industrial', data: sampleData() } });
    assert.equal(dup.status, 409);
  });

  test('anonymous visitors see only public data', async () => {
    const r = await a.call('GET', `/p/${passportId}?format=json`);
    assert.equal(r.status, 200);
    assert.equal(r.data.accessLevel, 'public');
    assert.equal(r.data.data.public.batteryModel, 'ACM-50');
    assert.equal(r.data.data.legitimateInterest, undefined);
    assert.equal(r.data.data.authorities, undefined);
    assert.equal(r.data.integrity.dataSha256, undefined);
  });

  test('HTML page escapes content, is compressed and supports ETag/304', async () => {
    const r = await a.call('GET', `/p/${passportId}?lang=ro`, { headers: { 'Accept-Encoding': 'br' } });
    assert.equal(r.status, 200);
    assert.ok(r.text.includes('Pașaportul bateriei'));
    assert.ok(r.text.includes('&lt;script&gt;'));
    assert.ok(!r.text.includes('<script>alert'));
    assert.ok(!r.text.includes('Remove 12 bolts'));
    assert.equal(r.headers.get('content-encoding'), 'br');
    const etag = r.headers.get('etag');
    const again = await a.call('GET', `/p/${passportId}?lang=ro`, { headers: { 'If-None-Match': etag } });
    assert.equal(again.status, 304);
  });

  test('restricted levels see their sections', async () => {
    const legit = await a.call('GET', `/p/${passportId}?format=json`, { token: legitToken });
    assert.equal(legit.data.accessLevel, 'legitimate_interest');
    assert.equal(legit.data.data.legitimateInterest.dismantlingInformation, 'Remove 12 bolts on the casing');
    assert.equal(legit.data.data.authorities, undefined);

    const auth = await a.call('GET', `/p/${passportId}?format=json`, { token: authorityToken });
    assert.deepEqual(auth.data.data.authorities.testReports, ['TR-001', 'TR-002']);
    assert.match(auth.data.integrity.dataSha256, /^[0-9a-f]{64}$/);

    assert.equal((await a.call('GET', `/p/${passportId}`, { token: 'dpa_invalid' })).status, 401);
  });

  test('browser sign-in with a token sets a session cookie', async () => {
    const bad = await a.call('POST', `/p/${passportId}/access`, {
      body: 'token=nope',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(bad.status, 401);

    const ok = await a.call('POST', `/p/${passportId}/access`, {
      body: `token=${encodeURIComponent(legitToken)}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(ok.status, 303);
    const cookie = ok.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /Secure/);
    const page = await a.call('GET', `/p/${passportId}?lang=en`, { headers: { Cookie: cookie.split(';')[0] } });
    assert.ok(page.text.includes('Remove 12 bolts'));
    assert.ok(page.text.includes('Recycler SA'));
  });

  test('updates create versions and the public cache follows them', async () => {
    const before = await a.call('GET', `/p/${passportId}?format=json`);
    assert.equal(before.data.data.public.ratedCapacity, '50 kWh');

    const same = await a.call('PUT', `/api/passports/${passportId}`, { token: key, json: { data: sampleData() } });
    assert.equal(same.data.changed, false);

    const up = await a.call('PUT', `/api/passports/${passportId}`, { token: key, json: { data: sampleData('49 kWh'), note: 'capacity re-measured', expectedVersion: 1 } });
    assert.equal(up.status, 200);
    assert.equal(up.data.version, 2);

    const stale = await a.call('PUT', `/api/passports/${passportId}`, { token: key, json: { data: sampleData('48 kWh'), expectedVersion: 1 } });
    assert.equal(stale.status, 409);

    const afterUpdate = await a.call('GET', `/p/${passportId}?format=json`);
    assert.equal(afterUpdate.data.version, 2);
    assert.equal(afterUpdate.data.data.public.ratedCapacity, '49 kWh');

    const full = await a.call('GET', `/api/passports/${passportId}`, { token: key });
    assert.equal(full.data.versions.length, 2);
    const v1 = await a.call('GET', `/api/passports/${passportId}/versions/1`, { token: key });
    assert.equal(v1.data.data.public.ratedCapacity, '50 kWh');
  });

  test('documents respect access levels and type checks', async () => {
    const wrongType = await a.call('POST', `/api/passports/${passportId}/documents?name=x.html`, {
      token: key,
      body: '<html></html>',
      headers: { 'Content-Type': 'text/html' },
    });
    assert.equal(wrongType.status, 415);

    const fake = await a.call('POST', `/api/passports/${passportId}/documents?name=fake.pdf`, {
      token: key,
      body: 'not a pdf',
      headers: { 'Content-Type': 'application/pdf' },
    });
    assert.equal(fake.status, 400);

    const pub = await a.call('POST', `/api/passports/${passportId}/documents?name=${encodeURIComponent('Declarație.pdf')}&access=public`, {
      token: key,
      body: PDF,
      headers: { 'Content-Type': 'application/pdf' },
    });
    assert.equal(pub.status, 201);
    const priv = await a.call('POST', `/api/passports/${passportId}/documents?name=test-report.pdf&access=authority`, {
      token: key,
      body: PDF,
      headers: { 'Content-Type': 'application/pdf' },
    });
    restrictedDocUrl = new URL(priv.data.url).pathname;

    const publicView = await a.call('GET', `/p/${passportId}?format=json`);
    assert.deepEqual(publicView.data.documents.map((d) => d.name), ['Declarație.pdf']);

    const dl = await a.call('GET', new URL(pub.data.url).pathname);
    assert.equal(dl.status, 200);
    assert.equal(dl.text, PDF.toString());
    assert.equal(dl.headers.get('content-type'), 'application/pdf');

    assert.equal((await a.call('GET', restrictedDocUrl)).status, 401);
    assert.equal((await a.call('GET', restrictedDocUrl, { token: legitToken })).status, 403);
    assert.equal((await a.call('GET', restrictedDocUrl, { token: authorityToken })).status, 200);
  });

  test('suspended clients stay publicly visible and can still export', async () => {
    await a.call('POST', `/admin/tenants/${tenantId}/suspend`, { token: ADMIN });
    const write = await a.call('PUT', `/api/passports/${passportId}`, { token: key, json: { data: sampleData('1 kWh') } });
    assert.equal(write.status, 403);
    assert.equal((await a.call('GET', `/p/${passportId}?format=json`)).status, 200);
    assert.equal((await a.call('GET', '/api/export', { token: key })).status, 200);
    await a.call('POST', `/admin/tenants/${tenantId}/reactivate`, { token: ADMIN });
  });

  test('export from one host and import into another keeps ids, versions and documents', async () => {
    const exp = await a.call('GET', '/api/export', { token: key });
    assert.equal(exp.data.format, 'dpp-hosting-export');
    assert.equal(exp.data.passports[0].versions.length, 2);

    const t = await b.call('POST', '/admin/tenants', { token: ADMIN, json: { name: 'Importer SRL' } });
    const keyB = t.data.apiKey.token;

    const tampered = structuredClone(exp.data);
    tampered.passports[0].versions[0].data.public.ratedCapacity = '999 kWh';
    const rejected = await b.call('POST', '/api/import', { token: keyB, json: tampered });
    assert.equal(rejected.data.errors, 1);

    const imp = await b.call('POST', '/api/import', { token: keyB, json: exp.data });
    assert.equal(imp.data.imported, 1);
    const again = await b.call('POST', '/api/import', { token: keyB, json: exp.data });
    assert.equal(again.data.skipped, 1);

    const onA = await a.call('GET', `/p/${passportId}?format=json`);
    const onB = await b.call('GET', `/p/${passportId}?format=json`);
    assert.equal(onB.status, 200);
    assert.equal(onB.data.integrity.publicSha256, onA.data.integrity.publicSha256);
    assert.equal(onB.data.version, 2);
    const doc = await b.call('GET', new URL(onB.data.documents[0].url).pathname);
    assert.equal(doc.text, PDF.toString());
  });

  test('audit log is hash-chained and append-only', async () => {
    const v = await a.call('GET', '/admin/audit/verify', { token: ADMIN });
    assert.equal(v.data.ok, true);
    assert.ok(v.data.entries >= 8);
    await assert.rejects(a.app.db.query("UPDATE dpp.audit_log SET actor = 'mallory'"), /append-only/);
    await assert.rejects(a.app.db.query('DELETE FROM dpp.passport_versions'), /immutable/);
    await assert.rejects(a.app.db.query('TRUNCATE dpp.audit_log CASCADE'), /append-only/);
  });

  test('unknown passports return 404', async () => {
    assert.equal((await a.call('GET', '/p/does-not-exist')).status, 404);
    assert.equal((await a.call('GET', '/p/does-not-exist?format=json')).data.error, 'passport_not_found');
  });
});
