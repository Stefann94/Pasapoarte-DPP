import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const ADMIN = 'test-admin-token-0123456789abcdef';
const PDF = Buffer.from('%PDF-1.4\n% model document\n%%EOF\n');

async function startInstance() {
  const dataDir = mkdtempSync(path.join(os.tmpdir(), 'dpp-portal-test-'));
  const config = loadConfig({ ADMIN_TOKEN: ADMIN, DATA_DIR: dataDir, PGLITE_DIR: 'memory://', BASE_URL: 'https://passport.example.test' });
  const app = await createApp(config);
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const call = async (method, p, { token, json, body, form, headers = {}, cookie } = {}) => {
    const h = { ...headers };
    if (token) h.Authorization = `Bearer ${token}`;
    if (cookie) h.Cookie = cookie;
    let payload = body;
    if (json !== undefined) {
      h['Content-Type'] = 'application/json';
      payload = JSON.stringify(json);
    } else if (form instanceof URLSearchParams) {
      h['Content-Type'] = 'application/x-www-form-urlencoded';
      payload = form.toString();
    } else if (form) payload = form; // FormData -> multipart
    const res = await fetch(base + p, { method, headers: h, body: payload, redirect: 'manual' });
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {}
    return { status: res.status, headers: res.headers, text, data };
  };
  return {
    call,
    async stop() {
      await app.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

const MODEL_DATA = {
  public: { manufacturer: 'Acme Cells', chemistry: 'LFP', ratedCapacityKWh: 100 },
  legitimateInterest: { dismantlingInformation: 'Manual chapter 7' },
  authorities: { testReports: 'IEC 62619 #42' },
};

describe('models, bulk passports and client portal', () => {
  let a;
  let b;
  let key;
  let tenantId;
  let modelId;
  let passports;
  let cookie;

  before(async () => {
    a = await startInstance();
    b = await startInstance();
    const t = await a.call('POST', '/admin/tenants', { token: ADMIN, json: { name: 'Importer SRL' } });
    key = t.data.apiKey.token;
    tenantId = t.data.tenant.id;
  });
  after(async () => {
    await a.stop();
    await b.stop();
  });

  test('a model holds the shared data; bulk creates passports in one request', async () => {
    const m = await a.call('POST', '/api/models', { token: key, json: { name: 'STOR-100', category: 'industrial', data: MODEL_DATA } });
    assert.equal(m.status, 201);
    modelId = m.data.id;
    assert.equal((await a.call('POST', '/api/models', { token: key, json: { name: 'STOR-100', category: 'industrial' } })).status, 409);

    const bulk = await a.call('POST', `/api/models/${modelId}/passports`, {
      token: key,
      json: {
        items: [
          { productIdentifier: 'SN-1', data: { public: { manufacturingDate: '2027-01-15' } } },
          { productIdentifier: 'SN-2' },
          { productIdentifier: 'SN-3' },
        ],
      },
    });
    assert.equal(bulk.status, 201);
    assert.equal(bulk.data.created, 3);
    passports = bulk.data.items;

    const dupInRequest = await a.call('POST', `/api/models/${modelId}/passports`, { token: key, json: { items: [{ productIdentifier: 'X' }, { productIdentifier: 'X' }] } });
    assert.equal(dupInRequest.status, 400);
    const existing = await a.call('POST', `/api/models/${modelId}/passports`, { token: key, json: { items: [{ productIdentifier: 'SN-2' }] } });
    assert.equal(existing.status, 409);
    assert.match(existing.data.message, /SN-2/);
  });

  test('public page merges model data with the battery data', async () => {
    const p1 = await a.call('GET', `/p/${passports[0].id}?format=json`);
    assert.equal(p1.data.data.public.manufacturer, 'Acme Cells');
    assert.equal(p1.data.data.public.manufacturingDate, '2027-01-15');
    assert.equal(p1.data.category, 'industrial');
    assert.equal(p1.data.model.name, 'STOR-100');
    assert.equal(p1.data.data.legitimateInterest, undefined);
    const p2 = await a.call('GET', `/p/${passports[1].id}?format=json`);
    assert.equal(p2.data.data.public.manufacturingDate, undefined);

    const html = await a.call('GET', `/p/${passports[0].id}?lang=ro`);
    assert.ok(html.text.includes('Producător'), 'known fields get translated labels');
  });

  test('model documents and model updates reach every passport', async () => {
    const doc = await a.call('POST', `/api/models/${modelId}/documents?name=Declaratie.pdf&access=public`, {
      token: key,
      body: PDF,
      headers: { 'Content-Type': 'application/pdf' },
    });
    assert.equal(doc.status, 201);
    for (const p of passports) {
      const view = await a.call('GET', `/p/${p.id}?format=json`);
      assert.deepEqual(view.data.documents.map((d) => d.name), ['Declaratie.pdf']);
      const dl = await a.call('GET', new URL(view.data.documents[0].url).pathname);
      assert.equal(dl.status, 200);
      assert.equal(dl.text, PDF.toString());
    }

    const upd = await a.call('PUT', `/api/models/${modelId}`, {
      token: key,
      json: { data: { ...MODEL_DATA, public: { ...MODEL_DATA.public, ratedCapacityKWh: 98 } }, expectedVersion: 1 },
    });
    assert.equal(upd.data.version, 2);
    const after = await a.call('GET', `/p/${passports[2].id}?format=json`);
    assert.equal(after.data.data.public.ratedCapacityKWh, 98);
    assert.equal(after.data.model.version, 2);
  });

  test('portal: activation link, login, and protected pages', async () => {
    assert.equal((await a.call('GET', '/portal')).status, 303);

    const u = await a.call('POST', `/admin/tenants/${tenantId}/users`, { token: ADMIN, json: { email: 'Ana@Example.com' } });
    assert.equal(u.status, 201);
    assert.equal(u.data.user.email, 'ana@example.com');
    const setupPath = new URL(u.data.setupUrl).pathname + new URL(u.data.setupUrl).search;
    assert.equal((await a.call('GET', setupPath)).status, 200);
    const token = new URL(u.data.setupUrl).searchParams.get('token');

    const mismatch = await a.call('POST', '/portal/setup', { form: new URLSearchParams({ token, password: 'parola-lunga-1', password2: 'alta-parola-2' }) });
    assert.equal(mismatch.status, 400);
    const set = await a.call('POST', '/portal/setup', { form: new URLSearchParams({ token, password: 'parola-lunga-1', password2: 'parola-lunga-1' }) });
    assert.equal(set.status, 303);
    assert.equal((await a.call('GET', setupPath)).status, 404, 'activation link works only once');

    const bad = await a.call('POST', '/portal/login', { form: new URLSearchParams({ email: 'ana@example.com', password: 'gresita-123456' }) });
    assert.equal(bad.status, 401);
    const ok = await a.call('POST', '/portal/login', { form: new URLSearchParams({ email: 'ANA@example.com', password: 'parola-lunga-1' }) });
    assert.equal(ok.status, 303);
    cookie = ok.headers.get('set-cookie').split(';')[0];
    assert.match(ok.headers.get('set-cookie'), /HttpOnly/);

    const dash = await a.call('GET', '/portal', { cookie });
    assert.equal(dash.status, 200);
    assert.ok(dash.text.includes('Importer SRL'));
    assert.ok(dash.text.includes('STOR-100'));

    const csrf = await a.call('POST', '/portal/models', {
      cookie,
      headers: { Origin: 'https://evil.example' },
      form: new URLSearchParams({ name: 'X', category: 'ev' }),
    });
    assert.equal(csrf.status, 403);

    // What real browsers send: same-origin form posts must work even with Origin: null.
    const browserLike = await a.call('POST', '/portal/login', {
      headers: { 'Sec-Fetch-Site': 'same-origin', Origin: 'null' },
      form: new URLSearchParams({ email: 'ana@example.com', password: 'parola-lunga-1' }),
    });
    assert.equal(browserLike.status, 303);
    const crossSite = await a.call('POST', '/portal/login', {
      headers: { 'Sec-Fetch-Site': 'cross-site', Origin: 'https://evil.example' },
      form: new URLSearchParams({ email: 'ana@example.com', password: 'parola-lunga-1' }),
    });
    assert.equal(crossSite.status, 403);
  });

  test('portal: create a model, add batteries from CSV, upload a document, get QR', async () => {
    const create = await a.call('POST', '/portal/models', {
      cookie,
      form: new URLSearchParams({
        name: 'E-BIKE 500',
        category: 'lmt',
        'public.manufacturer': 'Velo Power',
        'public.weightKg': '2,9',
        'public.__extra': 'Certificare: UN 38.3\nlinie fara format',
      }),
    });
    assert.equal(create.status, 400, 'malformed extra line is reported');
    assert.ok(create.text.includes('Denumire câmp: valoare'));

    const created = await a.call('POST', '/portal/models', {
      cookie,
      form: new URLSearchParams({ name: 'E-BIKE 500', category: 'lmt', 'public.manufacturer': 'Velo Power', 'public.weightKg': '2,9', 'public.__extra': 'Certificare: UN 38.3' }),
    });
    assert.equal(created.status, 303);
    const modelPath = created.headers.get('location').split('?')[0];
    const newModelId = modelPath.split('/').at(-1);

    const api = await a.call('GET', `/api/models/${newModelId}`, { token: key });
    assert.equal(api.data.data.public.weightKg, 2.9);
    assert.equal(api.data.data.public.Certificare, 'UN 38.3');

    const fd = new FormData();
    fd.set('items', '');
    fd.set('csv', new Blob(['serial;manufacturingDate\nEB-001;2027-02-01\nEB-002;2027-02-02\n'], { type: 'text/csv' }), 'baterii.csv');
    const bulk = await a.call('POST', `${modelPath}/passports`, { cookie, form: fd });
    assert.equal(bulk.status, 303);

    const page = await a.call('GET', modelPath, { cookie });
    assert.ok(page.text.includes('EB-001') && page.text.includes('EB-002'));

    const csv = await a.call('GET', `${modelPath}/passports.csv`, { cookie });
    assert.equal(csv.status, 200);
    assert.match(csv.text, /EB-001,https:\/\/passport\.example\.test\/p\//);

    const list = await a.call('GET', `/api/models/${newModelId}/passports`, { token: key });
    const eb1 = list.data.items.find((p) => p.productIdentifier === 'EB-001');
    const pub = await a.call('GET', `/p/${eb1.id}?format=json`);
    assert.equal(pub.data.data.public.manufacturingDate, '2027-02-01');
    assert.equal(pub.data.data.public.manufacturer, 'Velo Power');

    const docForm = new FormData();
    docForm.set('access', 'authority');
    docForm.set('file', new Blob([PDF], { type: 'application/pdf' }), 'Raport test.pdf');
    assert.equal((await a.call('POST', `${modelPath}/documents`, { cookie, form: docForm })).status, 303);
    const pubAfter = await a.call('GET', `/p/${eb1.id}?format=json`);
    assert.equal(pubAfter.data.documents.length, 0, 'authority document hidden from the public');

    const passportPage = await a.call('GET', `/portal/passports/${eb1.id}`, { cookie });
    assert.equal(passportPage.status, 200);
    assert.ok(passportPage.text.includes('<svg'));
    assert.ok(passportPage.text.includes('Raport test.pdf'));
    const docId = /\/portal\/documents\/([0-9a-f-]{36})/.exec(passportPage.text)[1];
    assert.equal((await a.call('GET', `/portal/documents/${docId}`, { cookie })).status, 200, 'owner can open restricted documents');

    const qr = await a.call('GET', `/portal/passports/${eb1.id}/qr.svg`, { cookie });
    assert.equal(qr.headers.get('content-type'), 'image/svg+xml');

    const edit = await a.call('POST', `/portal/passports/${eb1.id}`, {
      cookie,
      form: new URLSearchParams({ expectedVersion: '1', 'public.manufacturingDate': '2027-02-01', 'public.batteryStatus': 'remanufacturată' }),
    });
    assert.equal(edit.status, 303);
    const edited = await a.call('GET', `/p/${eb1.id}?format=json`);
    assert.equal(edited.data.version, 2);
    assert.equal(edited.data.data.public.batteryStatus, 'remanufacturată');
  });

  test('other tenants cannot see each other in the portal', async () => {
    const t2 = await a.call('POST', '/admin/tenants', { token: ADMIN, json: { name: 'Other SRL' } });
    const u2 = await a.call('POST', `/admin/tenants/${t2.data.tenant.id}/users`, { token: ADMIN, json: { email: 'bob@example.com' } });
    const token = new URL(u2.data.setupUrl).searchParams.get('token');
    await a.call('POST', '/portal/setup', { form: new URLSearchParams({ token, password: 'parola-bob-123', password2: 'parola-bob-123' }) });
    const login = await a.call('POST', '/portal/login', { form: new URLSearchParams({ email: 'bob@example.com', password: 'parola-bob-123' }) });
    const bob = login.headers.get('set-cookie').split(';')[0];
    assert.equal((await a.call('GET', `/portal/models/${modelId}`, { cookie: bob })).status, 404);
    assert.equal((await a.call('GET', `/portal/passports/${passports[0].id}`, { cookie: bob })).status, 404);
  });

  test('export v2 includes models and imports elsewhere with the same public pages', async () => {
    const exp = await a.call('GET', '/api/export', { token: key });
    assert.equal(exp.data.formatVersion, 2);
    assert.equal(exp.data.models.length, 2);

    const t = await b.call('POST', '/admin/tenants', { token: ADMIN, json: { name: 'Importer SRL' } });
    const imp = await b.call('POST', '/api/import', { token: t.data.apiKey.token, json: exp.data });
    assert.equal(imp.data.models.imported, 2);
    assert.equal(imp.data.errors, 0);

    for (const p of passports) {
      const onA = await a.call('GET', `/p/${p.id}?format=json`);
      const onB = await b.call('GET', `/p/${p.id}?format=json`);
      assert.equal(onB.data.integrity.publicSha256, onA.data.integrity.publicSha256);
      assert.equal(onB.data.documents.length, onA.data.documents.length);
    }
  });
});
