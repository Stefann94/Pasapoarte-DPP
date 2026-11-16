import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { fetchExternal } from '../src/mirror.js';

const ADMIN = 'test-admin-token-0123456789abcdef';

async function startInstance(extraEnv = {}) {
  const dataDir = mkdtempSync(path.join(os.tmpdir(), 'dpp-mirror-test-'));
  const config = loadConfig({ ADMIN_TOKEN: ADMIN, DATA_DIR: dataDir, PGLITE_DIR: 'memory://', BASE_URL: 'https://passport.example.test', ...extraEnv });
  const app = await createApp(config);
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const call = async (method, p, { token, json, form, headers = {}, cookie } = {}) => {
    const h = { ...headers };
    if (token) h.Authorization = `Bearer ${token}`;
    if (cookie) h.Cookie = cookie;
    let body;
    if (json !== undefined) {
      h['Content-Type'] = 'application/json';
      body = JSON.stringify(json);
    } else if (form instanceof URLSearchParams) {
      h['Content-Type'] = 'application/x-www-form-urlencoded';
      body = form.toString();
    } else if (form) body = form;
    const res = await fetch(base + p, { method, headers: h, body, redirect: 'manual' });
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

/** A stand-in for a manufacturer's passport server that can be switched off. */
function startExternalHost() {
  const state = { up: true, body: { data: { public: { manufacturer: 'Shenzhen Cells Ltd', chemistry: 'LFP' } } } };
  const server = http.createServer((req, res) => {
    if (!state.up) {
      res.writeHead(503);
      return res.end('down');
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(state.body));
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ state, url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() })),
  );
}

describe('EU mirror for externally hosted passports, admin console, password change', () => {
  let a;
  let host;
  let key;
  let tenantId;
  let passportId;

  before(async () => {
    a = await startInstance({ MIRROR_ALLOW_PRIVATE: '1' });
    host = await startExternalHost();
    const t = await a.call('POST', '/admin/tenants', { token: ADMIN, json: { name: 'Importer SRL' } });
    key = t.data.apiKey.token;
    tenantId = t.data.tenant.id;
  });
  after(async () => {
    await a.stop();
    host.close();
  });

  test('SSRF protection: private and metadata addresses are refused', async () => {
    await assert.rejects(fetchExternal('https://127.0.0.1/passport'), /non-public/);
    await assert.rejects(fetchExternal('https://169.254.169.254/latest/meta-data'), /non-public/);
    await assert.rejects(fetchExternal('http://example.com/'), /https/);
  });

  test('an external passport gets an EU copy immediately and redirects while the host is up', async () => {
    const r = await a.call('POST', '/api/passports', {
      token: key,
      json: { productIdentifier: 'CN-0001', category: 'industrial', externalUrl: `${host.url}/passport/CN-0001` },
    });
    assert.equal(r.status, 201);
    assert.equal(r.data.mirror.status, 'ok');
    passportId = r.data.id;

    const visit = await a.call('GET', `/p/${passportId}`);
    assert.equal(visit.status, 302);
    assert.equal(visit.headers.get('location'), `${host.url}/passport/CN-0001`);
  });

  test('when the external host goes down, visitors get the archived EU copy', async () => {
    host.state.up = false;
    const check = await a.call('POST', `/api/passports/${passportId}/mirror/check`, { token: key });
    assert.equal(check.data.status, 'down');

    const page = await a.call('GET', `/p/${passportId}?lang=ro`);
    assert.equal(page.status, 200);
    assert.ok(page.text.includes('copie arhivată în UE'));
    assert.ok(page.text.includes('Shenzhen Cells Ltd'));

    const json = await a.call('GET', `/p/${passportId}?format=json`);
    assert.equal(json.data.source, 'eu-mirror');
    assert.equal(json.data.mirror.data.data.public.chemistry, 'LFP');

    const raw = await a.call('GET', `/p/${passportId}/mirror/content`);
    assert.equal(raw.status, 200);
    assert.match(raw.headers.get('content-security-policy'), /sandbox/);
  });

  test('when the host comes back with new content, a new copy is stored and redirects resume', async () => {
    host.state.up = true;
    host.state.body = { data: { public: { manufacturer: 'Shenzhen Cells Ltd', chemistry: 'LFP', weightKg: 12 } } };
    const check = await a.call('POST', `/api/passports/${passportId}/mirror/check`, { token: key });
    assert.equal(check.data.status, 'ok');
    assert.equal(check.data.contentChanged, true);
    assert.equal((await a.call('GET', `/p/${passportId}`)).status, 302);

    const forced = await a.call('GET', `/p/${passportId}?mirror=1&format=json`);
    assert.equal(forced.data.mirror.data.data.public.weightKg, 12);

    const history = await a.call('GET', `/api/passports/${passportId}/mirror`, { token: key });
    assert.deepEqual(history.data.events.map((e) => e.status), ['ok', 'down', 'ok']);
  });

  test('the daily job only re-checks stale passports', async () => {
    const run = await a.call('GET', '/api/cron/mirror');
    assert.equal(run.status, 200);
    assert.equal(run.data.checked, 0, 'just checked, nothing is due');
  });

  test('export keeps the external address', async () => {
    const exp = await a.call('GET', '/api/export', { token: key });
    assert.equal(exp.data.passports.find((p) => p.id === passportId).externalUrl, `${host.url}/passport/CN-0001`);
  });

  test('console: sign-in, create a client with portal account, suspend, tokens, audit', async () => {
    assert.equal((await a.call('GET', '/console')).status, 303);
    assert.equal((await a.call('POST', '/console/login', { form: new URLSearchParams({ token: 'wrong' }) })).status, 401);
    const login = await a.call('POST', '/console/login', { form: new URLSearchParams({ token: ADMIN }) });
    assert.equal(login.status, 303);
    const cookie = login.headers.get('set-cookie').split(';')[0];

    const list = await a.call('GET', '/console', { cookie });
    assert.ok(list.text.includes('Importer SRL'));

    const created = await a.call('POST', '/console/tenants', { cookie, form: new URLSearchParams({ name: 'Nou SRL', vatId: 'RO1', email: 'ion@nou.ro' }) });
    assert.equal(created.status, 201);
    assert.match(created.text, /dpk_/);
    assert.match(created.text, /\/portal\/setup\?token=/);

    const tenants = await a.call('GET', '/admin/tenants', { token: ADMIN });
    const nou = tenants.data.items.find((t) => t.name === 'Nou SRL');
    const detail = await a.call('GET', `/console/tenants/${nou.id}`, { cookie });
    assert.ok(detail.text.includes('ion@nou.ro'));

    await a.call('POST', `/console/tenants/${nou.id}/status`, { cookie, form: new URLSearchParams({ action: 'suspend' }) });
    const after = await a.call('GET', '/admin/tenants', { token: ADMIN });
    assert.equal(after.data.items.find((t) => t.id === nou.id).status, 'suspended');

    const acc = await a.call('POST', '/console/accessors', { cookie, form: new URLSearchParams({ name: 'Reciclator SA', role: 'legitimate_interest' }) });
    assert.match(acc.text, /dpa_/);

    const audit = await a.call('GET', '/console/audit', { cookie });
    assert.ok(audit.text.includes('lanț intact'));

    const cross = await a.call('POST', '/console/tenants', { cookie, headers: { 'Sec-Fetch-Site': 'cross-site' }, form: new URLSearchParams({ name: 'Evil' }) });
    assert.equal(cross.status, 403);
  });

  test('portal: change password', async () => {
    const u = await a.call('POST', `/admin/tenants/${tenantId}/users`, { token: ADMIN, json: { email: 'maria@importer.ro' } });
    const token = new URL(u.data.setupUrl).searchParams.get('token');
    await a.call('POST', '/portal/setup', { form: new URLSearchParams({ token, password: 'parola-veche-1', password2: 'parola-veche-1' }) });
    const login = await a.call('POST', '/portal/login', { form: new URLSearchParams({ email: 'maria@importer.ro', password: 'parola-veche-1' }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];

    const wrong = await a.call('POST', '/portal/account', { cookie, form: new URLSearchParams({ current: 'gresit-12345', password: 'parola-noua-22', password2: 'parola-noua-22' }) });
    assert.equal(wrong.status, 400);
    const ok = await a.call('POST', '/portal/account', { cookie, form: new URLSearchParams({ current: 'parola-veche-1', password: 'parola-noua-22', password2: 'parola-noua-22' }) });
    assert.equal(ok.status, 303);
    assert.equal((await a.call('GET', '/portal', { cookie })).status, 303, 'old session closed');

    assert.equal((await a.call('POST', '/portal/login', { form: new URLSearchParams({ email: 'maria@importer.ro', password: 'parola-veche-1' }) })).status, 401);
    assert.equal((await a.call('POST', '/portal/login', { form: new URLSearchParams({ email: 'maria@importer.ro', password: 'parola-noua-22' }) })).status, 303);

    // The external passport shows the mirror panel in the portal.
    const fresh = await a.call('POST', '/portal/login', { form: new URLSearchParams({ email: 'maria@importer.ro', password: 'parola-noua-22' }) });
    const page = await a.call('GET', `/portal/passports/${passportId}`, { cookie: fresh.headers.get('set-cookie').split(';')[0] });
    assert.ok(page.text.includes('Găzduire externă și copia din UE'));
  });
});
