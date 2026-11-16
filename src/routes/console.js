import { createHmac } from 'node:crypto';
import { verifyAudit } from '../audit.js';
import { safeEqual } from '../crypto.js';
import { HttpError, parseCookies, readForm, redirect, sendHtml } from '../http.js';
import {
  createAccessor,
  createApiKey,
  createTenant,
  createUser,
  resetUser,
  revokeAccessor,
  revokeApiKey,
  setTenantStatus,
} from '../admin-ops.js';
import { checkOrigin } from '../portal/auth.js';
import { PORTAL_CSS } from '../portal/views.js';
import { esc } from '../views.js';

/*
 * Web console for the platform operator (Romanian). Sign-in with ADMIN_TOKEN;
 * the session is a signed, expiring cookie, so rotating ADMIN_TOKEN signs
 * everyone out. Secrets (API keys, tokens, activation links) are shown once.
 */

const COOKIE = 'dpp_console';
const TTL_SEC = 8 * 60 * 60;
const noStore = { 'Cache-Control': 'private, no-store' };

const sign = (secret, exp) => createHmac('sha256', secret).update(`console:${exp}`).digest('base64url');

function consoleCookie(config, value, maxAge) {
  return [`${COOKIE}=${value}`, 'HttpOnly', 'Path=/console', 'SameSite=Strict', `Max-Age=${maxAge}`, config.secureCookies ? 'Secure' : null]
    .filter(Boolean)
    .join('; ');
}

function isSignedIn(req, config) {
  const raw = parseCookies(req.headers.cookie)[COOKIE];
  if (!raw) return false;
  const [exp, sig] = raw.split('.');
  return Number(exp) > Date.now() / 1000 && Boolean(sig) && safeEqual(sig, sign(config.adminToken, exp));
}

const fmtDate = (iso) => (iso ? new Date(iso).toISOString().replace('T', ' ').slice(0, 16) : '—');
const ROLE_RO = { legitimate_interest: 'Interes legitim', authority: 'Autoritate' };

function layout({ title, body, signedIn = true, error }) {
  const nav = signedIn
    ? `<nav class="top"><a class="brand" href="/console">Pașapoarte DPP · Administrare</a>
       <a href="/console">Clienți</a><a href="/console/accessors">Acces restricționat</a><a href="/console/audit">Audit</a>
       <form method="post" action="/console/logout"><button class="link" type="submit">Ieșire</button></form></nav>`
    : '<nav class="top"><span class="brand">Pașapoarte DPP · Administrare</span></nav>';
  return `<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · Administrare</title><style>${PORTAL_CSS}
.secret{font-family:ui-monospace,Consolas,monospace;background:var(--bg);border:1px dashed var(--accent);border-radius:8px;padding:10px;overflow-wrap:anywhere}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.8rem;border:1px solid var(--line)}
.badge.bad{color:var(--danger);border-color:var(--danger)}</style></head>
<body><main>${nav}${error ? `<div class="errors">${esc(error)}</div>` : ''}<h1 style="margin:0 0 16px">${esc(title)}</h1>${body}</main></body></html>`;
}

/** One-time display of secrets; never stored in plain text on the server. */
function secretPage({ title, items, back, note }) {
  return layout({
    title,
    body: `<section><div class="errors" style="color:inherit;border-color:var(--accent)">Copiați acum valorile de mai jos.
      Din motive de securitate nu vor mai fi afișate niciodată.</div>
      ${items.map((i) => `<div class="field"><label>${esc(i.label)}</label><div class="secret">${esc(i.value)}</div>${i.hint ? `<p class="hint">${esc(i.hint)}</p>` : ''}</div>`).join('')}
      ${note ? `<p class="hint">${esc(note)}</p>` : ''}
      <a class="btn" href="${esc(back)}">Am copiat, continuă</a></section>`,
  });
}

/** Wraps console handlers: sign-in, same-origin POSTs, errors shown as pages. */
function guarded(handler) {
  return async (ctx) => {
    const { req, res, config } = ctx;
    if (req.method === 'POST') checkOrigin(req, config);
    if (!isSignedIn(req, config)) return redirect(res, '/console/login');
    try {
      return await handler(ctx);
    } catch (err) {
      if (err instanceof HttpError && err.status < 500) {
        return sendHtml(req, res, err.status, layout({ title: 'Operațiune refuzată', error: err.message, body: '<p><a href="/console">Înapoi</a></p>' }), noStore);
      }
      throw err;
    }
  };
}

export function registerConsoleRoutes(router) {
  // ------------------------------------------------------------ sign-in

  router.get('/console/login', ({ req, res }) => {
    sendHtml(req, res, 200, layout({
      title: 'Autentificare administrator',
      signedIn: false,
      body: `<section><form class="stack" method="post" action="/console/login">
        <div class="field"><label for="token">Token de administrator (ADMIN_TOKEN din .env / Vercel)</label>
        <input id="token" name="token" type="password" autocomplete="current-password" required></div>
        <button type="submit">Intră</button></form></section>`,
    }), noStore);
  });

  router.post('/console/login', async ({ req, res, config }) => {
    checkOrigin(req, config);
    const token = String((await readForm(req, 4096)).get('token') ?? '');
    if (!token || !safeEqual(token, config.adminToken)) {
      return sendHtml(req, res, 401, layout({ title: 'Autentificare administrator', signedIn: false, error: 'Token greșit.', body: '<p><a href="/console/login">Încearcă din nou</a></p>' }), noStore);
    }
    const exp = Math.floor(Date.now() / 1000) + TTL_SEC;
    redirect(res, '/console', { 'Set-Cookie': consoleCookie(config, `${exp}.${sign(config.adminToken, exp)}`, TTL_SEC) });
  });

  router.post('/console/logout', ({ req, res, config }) => {
    checkOrigin(req, config);
    redirect(res, '/console/login', { 'Set-Cookie': consoleCookie(config, '', 0) });
  });

  // ------------------------------------------------------------ tenants

  router.get('/console', guarded(async ({ req, res, st }) => {
    const tenants = await st.tenantListWithStats.all();
    const rows = tenants.length
      ? tenants.map((t) => `<tr><td><a href="/console/tenants/${esc(t.id)}">${esc(t.name)}</a></td><td>${esc(t.vat_id ?? '')}</td>
          <td>${t.status === 'active' ? '<span class="badge">activ</span>' : '<span class="badge bad">suspendat</span>'}</td>
          <td>${t.passport_count}</td><td>${t.user_count}</td><td>${esc(fmtDate(t.created_at))}</td></tr>`).join('')
      : '<tr><td colspan="6" class="muted">Niciun client încă.</td></tr>';
    sendHtml(req, res, 200, layout({
      title: 'Clienți',
      body: `<section><h2>Client nou</h2><form class="stack" method="post" action="/console/tenants"><div class="grid">
        <div class="field"><label for="name">Denumire firmă</label><input id="name" name="name" required maxlength="200"></div>
        <div class="field"><label for="vat">CUI / cod TVA (opțional)</label><input id="vat" name="vatId" maxlength="50"></div>
        <div class="field"><label for="email">E-mail cont portal (opțional)</label><input id="email" name="email" type="email"></div></div>
        <button type="submit">Creează clientul</button></form>
        <p class="hint">Primiți o singură dată cheia API și, dacă ați completat e-mailul, linkul de activare de trimis clientului.</p></section>
        <section><h2>Toți clienții</h2><div class="table-wrap"><table><thead><tr><th>Firmă</th><th>CUI</th><th>Stare</th><th>Pașapoarte</th><th>Conturi</th><th>Creat</th></tr></thead>
        <tbody>${rows}</tbody></table></div></section>`,
    }), noStore);
  }));

  router.post('/console/tenants', guarded(async ({ req, res, db, st, config }) => {
    const form = await readForm(req, 8192);
    const created = await createTenant(db, { name: String(form.get('name') ?? ''), vatId: String(form.get('vatId') ?? '') || null });
    const items = [{ label: 'Cheie API (pentru integrare automată)', value: created.apiKey.token, hint: 'Se folosește ca „Authorization: Bearer ...” în API.' }];
    const email = String(form.get('email') ?? '').trim();
    if (email) {
      const user = await createUser(db, st, config, created.tenant.id, email);
      items.push({ label: `Link de activare pentru ${user.user.email} (valabil 7 zile)`, value: user.setupUrl, hint: 'Trimiteți-l clientului: își setează singur parola.' });
    }
    sendHtml(req, res, 201, secretPage({ title: `Client creat: ${created.tenant.name}`, items, back: `/console/tenants/${created.tenant.id}` }), noStore);
  }));

  router.get('/console/tenants/:id', guarded(async ({ req, res, params, st }) => {
    const tenant = await st.tenantById.get(params.id);
    if (!tenant) throw new HttpError(404, 'tenant_not_found', 'Clientul nu există.');
    const [users, keys, count] = await Promise.all([st.userList.all(tenant.id), st.apiKeyList.all(tenant.id), st.passportCount.get(tenant.id)]);
    const base = `/console/tenants/${esc(tenant.id)}`;
    const userRows = users.length
      ? users.map((u) => `<tr><td>${esc(u.email)}</td><td>${u.active ? 'activ' : '<span class="muted">neactivat</span>'}</td><td>${esc(fmtDate(u.created_at))}</td>
          <td><form method="post" action="/console/users/${esc(u.id)}/reset"><button class="link" type="submit">Link nou de activare</button></form></td></tr>`).join('')
      : '<tr><td colspan="4" class="muted">Niciun cont.</td></tr>';
    const keyRows = keys.map((k) => `<tr><td class="mono">${esc(k.id.slice(0, 8))}…</td><td>${esc(fmtDate(k.created_at))}</td>
        <td>${k.revoked_at ? `<span class="badge bad">revocată ${esc(fmtDate(k.revoked_at))}</span>` : '<span class="badge">activă</span>'}</td>
        <td>${k.revoked_at ? '' : `<form method="post" action="/console/api-keys/${esc(k.id)}/revoke"><input type="hidden" name="tenant" value="${esc(tenant.id)}"><button class="link" type="submit">Revocă</button></form>`}</td></tr>`).join('');
    const suspended = tenant.status !== 'active';
    sendHtml(req, res, 200, layout({
      title: tenant.name,
      body: `<section class="meta"><div><span>Stare</span><strong>${suspended ? 'Suspendat' : 'Activ'}</strong></div>
        <div><span>CUI</span><strong>${esc(tenant.vat_id ?? '—')}</strong></div><div><span>Pașapoarte</span><strong>${count.n}</strong></div>
        <div><span>Creat</span><strong>${esc(fmtDate(tenant.created_at))}</strong></div></section>
        <section><h2>Suspendare</h2><p class="hint">Suspendarea blochează doar modificările. Pașapoartele existente rămân publice, iar clientul își poate exporta datele.</p>
        <form method="post" action="${base}/status"><input type="hidden" name="action" value="${suspended ? 'reactivate' : 'suspend'}">
        <button class="${suspended ? '' : 'secondary'}" type="submit">${suspended ? 'Reactivează' : 'Suspendă'}</button></form></section>
        <section><h2>Conturi în portal</h2><div class="table-wrap"><table><thead><tr><th>E-mail</th><th>Stare</th><th>Creat</th><th></th></tr></thead><tbody>${userRows}</tbody></table></div>
        <form method="post" action="${base}/users" style="margin-top:12px"><input name="email" type="email" placeholder="email@firma.ro" required><button type="submit">Adaugă cont</button></form></section>
        <section><h2>Chei API</h2><div class="table-wrap"><table><thead><tr><th>Cheie</th><th>Creată</th><th>Stare</th><th></th></tr></thead><tbody>${keyRows}</tbody></table></div>
        <form method="post" action="${base}/api-keys" style="margin-top:12px"><button class="secondary" type="submit">Generează cheie nouă</button></form></section>`,
    }), noStore);
  }));

  router.post('/console/tenants/:id/status', guarded(async ({ req, res, params, db }) => {
    const action = (await readForm(req, 1024)).get('action') === 'reactivate' ? 'reactivate' : 'suspend';
    await setTenantStatus(db, params.id, action);
    redirect(res, `/console/tenants/${encodeURIComponent(params.id)}`);
  }));

  router.post('/console/tenants/:id/users', guarded(async ({ req, res, params, db, st, config }) => {
    const email = String((await readForm(req, 4096)).get('email') ?? '');
    const r = await createUser(db, st, config, params.id, email);
    sendHtml(req, res, 201, secretPage({
      title: 'Cont creat',
      items: [{ label: `Link de activare pentru ${r.user.email} (valabil 7 zile, o singură folosire)`, value: r.setupUrl }],
      back: `/console/tenants/${params.id}`,
    }), noStore);
  }));

  router.post('/console/users/:id/reset', guarded(async ({ req, res, params, db, st, config }) => {
    const user = await st.userById.get(params.id);
    const r = await resetUser(db, st, config, params.id);
    sendHtml(req, res, 200, secretPage({
      title: 'Link nou de activare',
      items: [{ label: `Pentru ${user.email} (valabil 7 zile). Sesiunile deschise au fost închise.`, value: r.setupUrl }],
      back: `/console/tenants/${user.tenant_id}`,
    }), noStore);
  }));

  router.post('/console/tenants/:id/api-keys', guarded(async ({ req, res, params, db, st }) => {
    const key = await createApiKey(db, st, params.id);
    sendHtml(req, res, 201, secretPage({ title: 'Cheie API nouă', items: [{ label: 'Cheie API', value: key.token }], back: `/console/tenants/${params.id}` }), noStore);
  }));

  router.post('/console/api-keys/:id/revoke', guarded(async ({ req, res, params, db }) => {
    const tenant = String((await readForm(req, 1024)).get('tenant') ?? '');
    await revokeApiKey(db, params.id);
    redirect(res, tenant ? `/console/tenants/${encodeURIComponent(tenant)}` : '/console');
  }));

  // ------------------------------------------------------------ restricted-access organisations

  router.get('/console/accessors', guarded(async ({ req, res, st }) => {
    const items = await st.accessorList.all();
    const rows = items.length
      ? items.map((a) => `<tr><td>${esc(a.name)}</td><td>${esc(ROLE_RO[a.role])}</td><td>${esc(fmtDate(a.created_at))}</td>
          <td>${a.revoked_at ? `<span class="badge bad">revocat</span>` : `<form method="post" action="/console/accessors/${esc(a.id)}/revoke"><button class="link" type="submit">Revocă</button></form>`}</td></tr>`).join('')
      : '<tr><td colspan="4" class="muted">Nicio organizație.</td></tr>';
    sendHtml(req, res, 200, layout({
      title: 'Acces restricționat',
      body: `<section><p class="hint">Organizațiile de aici (reciclatori, service-uri, autorități) primesc un token cu care văd secțiunile restricționate ale pașapoartelor.
        Emiteți tokenuri numai după verificarea identității și a interesului legitim. Regulile UE privind drepturile de acces sunt încă în proiect.</p>
        <form method="post" action="/console/accessors"><input name="name" placeholder="Denumirea organizației" required maxlength="200">
        <select name="role"><option value="legitimate_interest">Interes legitim</option><option value="authority">Autoritate</option></select>
        <button type="submit">Emite token</button></form></section>
        <section><div class="table-wrap"><table><thead><tr><th>Organizație</th><th>Rol</th><th>Creat</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></section>`,
    }), noStore);
  }));

  router.post('/console/accessors', guarded(async ({ req, res, db }) => {
    const form = await readForm(req, 4096);
    const r = await createAccessor(db, { name: String(form.get('name') ?? ''), role: String(form.get('role') ?? '') });
    sendHtml(req, res, 201, secretPage({
      title: `Token pentru ${r.accessor.name}`,
      items: [{ label: `Token (${ROLE_RO[r.accessor.role]})`, value: r.token, hint: 'Se introduce în secțiunea „Acces restricționat” a oricărui pașaport sau se folosește ca Bearer în API.' }],
      back: '/console/accessors',
    }), noStore);
  }));

  router.post('/console/accessors/:id/revoke', guarded(async ({ res, params, db }) => {
    await revokeAccessor(db, params.id);
    redirect(res, '/console/accessors');
  }));

  // ------------------------------------------------------------ audit

  router.get('/console/audit', guarded(async ({ req, res, st }) => {
    const [check, items] = await Promise.all([verifyAudit(st), st.auditRecent.all(100)]);
    const rows = items.map((e) => `<tr><td>${e.seq}</td><td>${esc(fmtDate(e.ts))}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td>
        <td class="mono">${esc((e.target ?? '').slice(0, 12))}</td></tr>`).join('');
    sendHtml(req, res, 200, layout({
      title: 'Jurnal de audit',
      body: `<section>${check.ok
        ? `<p><span class="badge">lanț intact</span> ${check.entries} înregistrări verificate. Ultimul hash: <span class="mono">${esc(check.head)}</span></p>`
        : `<p><span class="badge bad">lanț rupt</span> la înregistrarea ${check.brokenAtSeq}. Investigați imediat.</p>`}
        <p class="hint">Fiecare înregistrare include hash-ul celei anterioare: orice modificare sau ștergere ulterioară devine detectabilă.</p></section>
        <section><div class="table-wrap"><table><thead><tr><th>#</th><th>Data</th><th>Cine</th><th>Acțiune</th><th>Obiect</th></tr></thead><tbody>${rows}</tbody></table></div></section>`,
    }), noStore);
  }));
}
