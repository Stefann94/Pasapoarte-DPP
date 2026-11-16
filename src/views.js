import { fieldLabel } from './fields.js';

/* Server-rendered HTML for the public passport page. No JavaScript is shipped:
   the page is a single small HTML response with inline CSS, so it loads fast on
   a phone right after a QR scan. */

const STRINGS = {
  en: {
    title: 'Battery passport',
    productIdentifier: 'Battery identifier',
    model: 'Model',
    category: 'Category',
    version: 'Version',
    updatedAt: 'Last updated',
    fingerprint: 'Public data fingerprint (SHA-256)',
    public: 'Public information',
    legitimateInterest: 'Information for persons with a legitimate interest',
    authorities: 'Information for notified bodies, market surveillance authorities and the Commission',
    documents: 'Documents',
    noDocuments: 'No documents available.',
    empty: 'No information provided.',
    restricted: 'Restricted access',
    restrictedHelp: 'Authorised organisations can enter their access token to view additional information.',
    token: 'Access token',
    signIn: 'Sign in',
    signedInAs: 'Signed in as',
    signOut: 'Sign out',
    invalidToken: 'Invalid or revoked access token.',
    footer: 'Hosted on behalf of the responsible economic operator, who is responsible for the content.',
    notFound: 'Passport not found',
    error: 'Error',
    landing: 'Digital product passport hosting',
    landingText: 'Scan the QR code on a battery to view its passport.',
    portal: 'Client portal: sign in',
    mirrorTitle: 'Battery passport (archived EU copy)',
    mirrorNotice: 'The primary host of this passport is currently unavailable. You are viewing the copy archived in the EU.',
    mirrorArchivedAt: 'Archived on',
    mirrorSource: 'Original address',
    mirrorOpen: 'Open the archived passport',
    mirrorFingerprint: 'Archived copy fingerprint (SHA-256)',
    categories: {
      ev: 'Electric vehicle battery',
      lmt: 'Light means of transport battery',
      industrial: 'Industrial battery (> 2 kWh)',
    },
    roles: { legitimate_interest: 'legitimate interest', authority: 'authority' },
  },
  ro: {
    title: 'Pașaportul bateriei',
    productIdentifier: 'Identificatorul bateriei',
    model: 'Model',
    category: 'Categorie',
    version: 'Versiune',
    updatedAt: 'Ultima actualizare',
    fingerprint: 'Amprenta datelor publice (SHA-256)',
    public: 'Informații publice',
    legitimateInterest: 'Informații pentru persoanele cu interes legitim',
    authorities: 'Informații pentru organismele notificate, autoritățile de supraveghere a pieței și Comisie',
    documents: 'Documente',
    noDocuments: 'Nu există documente disponibile.',
    empty: 'Nu au fost furnizate informații.',
    restricted: 'Acces restricționat',
    restrictedHelp: 'Organizațiile autorizate își pot introduce tokenul de acces pentru a vedea informații suplimentare.',
    token: 'Token de acces',
    signIn: 'Autentificare',
    signedInAs: 'Autentificat ca',
    signOut: 'Ieșire',
    invalidToken: 'Token de acces invalid sau revocat.',
    footer: 'Găzduit în numele operatorului economic responsabil, care răspunde de conținut.',
    notFound: 'Pașaportul nu a fost găsit',
    error: 'Eroare',
    landing: 'Găzduire pașapoarte digitale de produs',
    landingText: 'Scanați codul QR de pe baterie pentru a vedea pașaportul.',
    portal: 'Portal clienți: autentificare',
    mirrorTitle: 'Pașaportul bateriei (copie arhivată în UE)',
    mirrorNotice: 'Serverul principal al acestui pașaport nu este disponibil momentan. Vedeți copia arhivată în UE.',
    mirrorArchivedAt: 'Arhivat la',
    mirrorSource: 'Adresa originală',
    mirrorOpen: 'Deschide pașaportul arhivat',
    mirrorFingerprint: 'Amprenta copiei arhivate (SHA-256)',
    categories: {
      ev: 'Baterie pentru vehicul electric',
      lmt: 'Baterie pentru mijloace ușoare de transport',
      industrial: 'Baterie industrială (> 2 kWh)',
    },
    roles: { legitimate_interest: 'interes legitim', authority: 'autoritate' },
  },
};

export const LANGS = Object.keys(STRINGS);

export function pickLang(req, url) {
  const q = url.searchParams.get('lang');
  if (q && STRINGS[q]) return q;
  const accept = (req.headers['accept-language'] ?? '').toLowerCase();
  const first = accept.split(',')[0]?.trim().slice(0, 2);
  return STRINGS[first] ? first : 'en';
}

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export { CSS as PUBLIC_CSS };
export const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--text:#16181d;--muted:#5d6470;--line:#e2e5ea;--accent:#0b6e4f;--accent-text:#fff;--danger:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--text:#e8eaee;--muted:#9aa2ae;--line:#2a2f38;--accent:#3fbf8f;--accent-text:#0f1115;--danger:#f97066}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;margin:8px 0 16px}
h1{font-size:1.5rem;margin:0}
h2{font-size:1.1rem;margin:0 0 12px}
.lang a{color:var(--muted);margin-left:8px;text-decoration:none}.lang a[aria-current]{color:var(--text);font-weight:600}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.meta div span{display:block;color:var(--muted);font-size:.85rem}
.meta div strong{overflow-wrap:anywhere}
dl{margin:0;display:grid;grid-template-columns:minmax(120px,32%) 1fr;gap:6px 16px}
dt{color:var(--muted);overflow-wrap:anywhere}dd{margin:0;overflow-wrap:anywhere;white-space:pre-line}
dd dl{border-left:2px solid var(--line);padding-left:10px}
ol{margin:0;padding-left:20px}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:.8rem;overflow-wrap:anywhere}
a{color:var(--accent)}
ul.docs{list-style:none;margin:0;padding:0}ul.docs li{padding:8px 0;border-top:1px solid var(--line)}ul.docs li:first-child{border-top:0}
form{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
input{flex:1 1 240px;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font:inherit}
button{padding:10px 16px;border:0;border-radius:8px;background:var(--accent);color:var(--accent-text);font:inherit;font-weight:600;cursor:pointer}
.error{color:var(--danger);margin:8px 0 0}
footer{color:var(--muted);font-size:.85rem;padding:8px 0 24px}
@media (max-width:560px){dl{grid-template-columns:1fr}dt{margin-top:6px}}
`;

function layout({ lang, title, body, langLinkBase }) {
  const t = STRINGS[lang];
  const langLinks = langLinkBase
    ? `<nav class="lang">${LANGS.map(
        (l) => `<a href="${esc(langLinkBase)}?lang=${l}"${l === lang ? ' aria-current="true"' : ''}>${l.toUpperCase()}</a>`,
      ).join('')}</nav>`
    : '';
  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${CSS}</style></head>
<body><main><header><h1>${esc(title)}</h1>${langLinks}</header>${body}<footer>${esc(t.footer)}</footer></main></body></html>`;
}

function renderValue(v, t) {
  if (v === null || v === undefined || v === '') return '<span class="muted">—</span>';
  if (Array.isArray(v)) {
    return v.length ? `<ol>${v.map((x) => `<li>${renderValue(x, t)}</li>`).join('')}</ol>` : '<span class="muted">—</span>';
  }
  if (typeof v === 'object') {
    const keys = Object.keys(v);
    if (!keys.length) return '<span class="muted">—</span>';
    return `<dl>${keys.map((k) => `<dt>${esc(k)}</dt><dd>${renderValue(v[k], t)}</dd>`).join('')}</dl>`;
  }
  const s = String(v);
  if (/^https?:\/\/[^\s"'<>]+$/i.test(s)) return `<a href="${esc(s)}" rel="noopener nofollow noreferrer">${esc(s)}</a>`;
  return esc(s);
}

function dataSection(title, obj, t, lang) {
  const keys = obj ? Object.keys(obj) : [];
  const body = keys.length
    ? `<dl>${keys.map((k) => `<dt>${esc(fieldLabel(k, lang))}</dt><dd>${renderValue(obj[k], t)}</dd>`).join('')}</dl>`
    : `<p class="muted">${esc(t.empty)}</p>`;
  return `<section><h2>${esc(title)}</h2>${body}</section>`;
}

const formatSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`);

export function renderPassportPage({ view, accessor, lang, error }) {
  const t = STRINGS[lang];
  const path = `/p/${encodeURIComponent(view.id)}`;
  const updated = new Date(view.updatedAt).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

  const meta = `<section class="meta">
    <div><span>${esc(t.productIdentifier)}</span><strong>${esc(view.productIdentifier)}</strong></div>
    <div><span>${esc(t.category)}</span><strong>${esc(t.categories[view.category] ?? view.category)}</strong></div>
    ${view.model ? `<div><span>${esc(t.model)}</span><strong>${esc(view.model.name)}</strong></div>` : ''}
    <div><span>${esc(t.version)}</span><strong>${view.version}</strong></div>
    <div><span>${esc(t.updatedAt)}</span><strong>${esc(updated)}</strong></div>
    <div style="grid-column:1/-1"><span>${esc(t.fingerprint)}</span><span class="mono">${esc(view.integrity.publicSha256)}</span></div>
  </section>`;

  let sections = dataSection(t.public, view.data.public, t, lang);
  if (view.data.legitimateInterest) sections += dataSection(t.legitimateInterest, view.data.legitimateInterest, t, lang);
  if (view.data.authorities) sections += dataSection(t.authorities, view.data.authorities, t, lang);

  const docs = view.documents.length
    ? `<ul class="docs">${view.documents
        .map(
          (d) =>
            `<li><a href="${esc(new URL(d.url).pathname)}">${esc(d.name)}</a> <span class="muted">· ${esc(d.contentType)} · ${formatSize(d.size)}</span></li>`,
        )
        .join('')}</ul>`
    : `<p class="muted">${esc(t.noDocuments)}</p>`;

  const access = accessor
    ? `<section><h2>${esc(t.restricted)}</h2><p>${esc(t.signedInAs)} <strong>${esc(accessor.name)}</strong> (${esc(t.roles[accessor.role])})</p>
       <form method="post" action="${path}/logout?lang=${lang}"><button type="submit">${esc(t.signOut)}</button></form></section>`
    : `<section><h2>${esc(t.restricted)}</h2><p class="muted">${esc(t.restrictedHelp)}</p>
       <form method="post" action="${path}/access?lang=${lang}"><input name="token" type="password" autocomplete="off" aria-label="${esc(t.token)}" placeholder="${esc(t.token)}" required><button type="submit">${esc(t.signIn)}</button></form>
       ${error ? `<p class="error">${esc(t.invalidToken)}</p>` : ''}</section>`;

  return layout({
    lang,
    title: t.title,
    langLinkBase: path,
    body: `${meta}${sections}<section><h2>${esc(t.documents)}</h2>${docs}</section>${access}`,
  });
}

export function renderErrorPage({ lang, status, message }) {
  const t = STRINGS[lang];
  const title = status === 404 ? t.notFound : `${t.error} ${status}`;
  return layout({ lang, title, body: `<section><p>${esc(message)}</p></section>` });
}

export function renderLanding(lang) {
  const t = STRINGS[lang];
  return layout({ lang, title: t.landing, langLinkBase: '/', body: `<section><p>${esc(t.landingText)}</p></section><section><a href="/portal/login">${esc(t.portal)}</a></section>` });
}

/** Page shown when an external passport's host is down: the EU-archived copy. */
export function renderMirrorPage({ lang, passport, mirror }) {
  const t = STRINGS[lang];
  const path = `/p/${encodeURIComponent(passport.id)}`;
  const archived = mirror.fetchedAt ? new Date(mirror.fetchedAt).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
  const meta = `<section class="meta">
    <div><span>${esc(t.productIdentifier)}</span><strong>${esc(passport.product_identifier)}</strong></div>
    <div><span>${esc(t.mirrorArchivedAt)}</span><strong>${esc(archived)}</strong></div>
    <div style="grid-column:1/-1"><span>${esc(t.mirrorSource)}</span><span class="mono">${esc(mirror.externalUrl)}</span></div>
    <div style="grid-column:1/-1"><span>${esc(t.mirrorFingerprint)}</span><span class="mono">${esc(mirror.sha256)}</span></div>
  </section>`;
  let content;
  if (mirror.data && typeof mirror.data === 'object') {
    // Our own export format ({data: {public, ...}}) or any JSON document.
    const pub = mirror.data?.data?.public ?? mirror.data?.public ?? mirror.data;
    content = dataSection(t.public, pub, t, lang);
  } else {
    content = `<section><p><a href="${path}/mirror/content">${esc(t.mirrorOpen)}</a> <span class="muted">(${esc(mirror.contentType ?? '')})</span></p></section>`;
  }
  return layout({
    lang,
    title: t.mirrorTitle,
    langLinkBase: path,
    body: `<section style="border-color:var(--accent)"><p>${esc(t.mirrorNotice)}</p></section>${meta}${content}`,
  });
}
