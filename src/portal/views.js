/* Client portal pages (Romanian). Server-rendered, no JavaScript. */
import { fieldLabel, fieldsFor, SECTIONS } from '../fields.js';
import { CATEGORIES } from '../passports.js';
import { esc, PUBLIC_CSS } from '../views.js';

const CATEGORY_RO = {
  ev: 'Baterie pentru vehicul electric',
  lmt: 'Baterie pentru mijloace ușoare de transport',
  industrial: 'Baterie industrială (> 2 kWh)',
};
const ACCESS_RO = {
  public: 'Public',
  legitimate_interest: 'Interes legitim',
  authority: 'Autorități',
};
export const FLASH = {
  model_created: 'Modelul a fost creat. Acum puteți adăuga bateriile.',
  model_updated: 'Modelul a fost actualizat. Toate pașapoartele modelului afișează noile date.',
  model_unchanged: 'Nu a fost nicio modificare de salvat.',
  passports_created: 'Pașapoartele au fost create.',
  passport_updated: 'Pașaportul a fost actualizat.',
  document_added: 'Documentul a fost încărcat.',
  documents_added: 'Fișierele au fost încărcate.',
  document_removed: 'Documentul a fost ascuns.',
  password_set: 'Parola a fost setată. Vă puteți autentifica.',
  password_changed: 'Parola a fost schimbată.',
  external_set: 'Adresa externă a fost salvată și verificată.',
  external_removed: 'Pașaportul este din nou găzduit pe platformă.',
  mirror_checked: 'Verificarea a fost făcută.',
};

const CSS = `${PUBLIC_CSS}
main{max-width:1080px}
nav.top{display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:12px 0;border-bottom:1px solid var(--line);margin-bottom:16px}
nav.top .brand{font-weight:700;margin-right:auto;color:var(--text);text-decoration:none}
nav.top a{text-decoration:none}
nav.top form{margin:0}
.btn,button{display:inline-block;padding:9px 14px;border:0;border-radius:8px;background:var(--accent);color:var(--accent-text);font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
.btn.secondary,button.secondary{background:transparent;color:var(--text);border:1px solid var(--line)}
button.link{background:none;color:var(--muted);padding:0;font-weight:400;text-decoration:underline}
table{width:100%;border-collapse:collapse;font-size:.95rem}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}
.table-wrap{overflow-x:auto}
.flash{background:color-mix(in srgb,var(--accent) 14%,transparent);border:1px solid var(--accent);border-radius:10px;padding:10px 14px;margin-bottom:16px}
.errors{border:1px solid var(--danger);color:var(--danger);border-radius:10px;padding:10px 14px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
label{display:block;font-size:.9rem;color:var(--muted);margin-bottom:4px}
.field{margin-bottom:10px}
form.stack{display:block}
form.stack input,form.stack select,form.stack textarea{width:100%}
select,textarea{padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font:inherit}
textarea{min-height:80px;resize:vertical}
.hint{color:var(--muted);font-size:.85rem;margin:4px 0 0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.stats div{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.stats strong{font-size:1.6rem;display:block}
.qr svg{width:180px;height:180px;background:#fff;padding:6px;border-radius:8px}
.pager{display:flex;gap:12px;margin-top:12px}
`;

export { CSS as PORTAL_CSS };

function layout({ title, user, body, flash, errors }) {
  const nav = user
    ? `<nav class="top"><a class="brand" href="/portal">Pașapoarte DPP · ${esc(user.tenantName)}</a>
        <a href="/portal">Modele</a><a href="/portal/export">Export</a><a href="/portal/account">Cont</a>
        <form method="post" action="/portal/logout"><button class="link" type="submit">Ieșire</button></form></nav>`
    : `<nav class="top"><span class="brand">Pașapoarte DPP · Portal clienți</span></nav>`;
  const flashHtml = flash && FLASH[flash] ? `<div class="flash">${esc(FLASH[flash])}</div>` : '';
  const errorHtml = errors?.length ? `<div class="errors">${errors.map((e) => `<div>${esc(e)}</div>`).join('')}</div>` : '';
  const suspended = user && user.status !== 'active'
    ? '<div class="errors">Contul este suspendat: pașapoartele rămân publice, dar modificările sunt blocate.</div>'
    : '';
  return `<!doctype html>
<html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · Pașapoarte DPP</title><style>${CSS}</style><script src="/portal/assets/upload.js" defer></script></head>
<body><main>${nav}${suspended}${flashHtml}${errorHtml}<h1 style="margin:0 0 16px">${esc(title)}</h1>${body}</main></body></html>`;
}

const fmtDate = (iso) => (iso ? new Date(iso).toISOString().replace('T', ' ').slice(0, 16) : '');
const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`);

// ------------------------------------------------------------------ auth pages

export function loginPage({ error, email = '', flash }) {
  return layout({
    title: 'Autentificare',
    flash,
    errors: error ? [error] : [],
    body: `<section><form class="stack" method="post" action="/portal/login">
      <div class="field"><label for="email">E-mail</label><input id="email" name="email" type="email" autocomplete="username" required value="${esc(email)}"></div>
      <div class="field"><label for="password">Parolă</label><input id="password" name="password" type="password" autocomplete="current-password" required></div>
      <button type="submit">Intră în cont</button></form></section>`,
  });
}

export function setupPage({ token, email, error }) {
  return layout({
    title: 'Setați parola',
    errors: error ? [error] : [],
    body: `<section><p>Cont: <strong>${esc(email)}</strong></p>
      <form class="stack" method="post" action="/portal/setup">
      <input type="hidden" name="token" value="${esc(token)}">
      <div class="field"><label for="p1">Parolă nouă (minimum 10 caractere)</label><input id="p1" name="password" type="password" autocomplete="new-password" minlength="10" required></div>
      <div class="field"><label for="p2">Repetați parola</label><input id="p2" name="password2" type="password" autocomplete="new-password" minlength="10" required></div>
      <button type="submit">Salvează parola</button></form></section>`,
  });
}

export function messagePage({ title, message, user }) {
  return layout({ title, user, body: `<section><p>${esc(message)}</p><p><a href="/portal">Înapoi la portal</a></p></section>` });
}

// ------------------------------------------------------------------ dashboard

export function dashboardPage({ user, models, recent, totalPassports, mirror, flash }) {
  const rows = models.length
    ? models
        .map(
          (m) => `<tr><td><a href="/portal/models/${esc(m.id)}">${esc(m.name)}</a></td><td>${esc(CATEGORY_RO[m.category] ?? m.category)}</td>
          <td>${m.passport_count}</td><td>v${m.current_version}</td><td>${esc(fmtDate(m.updated_at))}</td></tr>`,
        )
        .join('')
    : '<tr><td colspan="5" class="muted">Nu există încă modele. Începeți prin a crea primul model de baterie.</td></tr>';
  const recentRows = recent
    .map(
      (p) => `<tr><td><a href="/portal/passports/${esc(p.id)}">${esc(p.product_identifier)}</a></td><td>${esc(p.model_name ?? '—')}</td>
      <td>${esc(fmtDate(p.updated_at))}</td></tr>`,
    )
    .join('');
  return layout({
    title: 'Modele de baterii',
    user,
    flash,
    body: `<div class="stats"><div><span class="muted">Modele</span><strong>${models.length}</strong></div>
      <div><span class="muted">Pașapoarte</span><strong>${totalPassports}</strong></div>
      ${mirror?.total ? `<div><span class="muted">Găzduite extern, cu copie UE</span><strong>${mirror.total}</strong>
        <span class="${mirror.down ? '' : 'muted'}" style="${mirror.down ? 'color:var(--danger)' : ''}">${mirror.down ? `${mirror.down} cu serverul extern căzut` : 'toate funcționale'}</span></div>` : ''}</div>
      <section style="margin-top:16px"><div class="row" style="justify-content:space-between"><h2>Modele</h2>
      <a class="btn" href="/portal/models/new">+ Model nou</a></div>
      <p class="hint">Datele comune (producător, chimie, capacitate, documente) se completează o singură dată per model.
      Apoi adăugați bateriile doar prin numărul de serie.</p>
      <div class="table-wrap"><table><thead><tr><th>Model</th><th>Categorie</th><th>Baterii</th><th>Versiune</th><th>Actualizat</th></tr></thead>
      <tbody>${rows}</tbody></table></div></section>
      ${recent.length ? `<section><h2>Pașapoarte actualizate recent</h2><div class="table-wrap"><table><thead><tr><th>Identificator</th><th>Model</th><th>Actualizat</th></tr></thead><tbody>${recentRows}</tbody></table></div></section>` : ''}`,
  });
}

// ------------------------------------------------------------------ data forms

function fieldInput(name, field, value) {
  const v = esc(value ?? '');
  if (field.type === 'textarea') return `<textarea id="${name}" name="${name}">${v}</textarea>`;
  const type = field.type === 'date' ? 'date' : 'text';
  const mode = field.type === 'number' ? ' inputmode="decimal"' : '';
  return `<input id="${name}" name="${name}" type="${type}"${mode} value="${v}">`;
}

/** Field groups per section, for model-level or item-level data. */
export function dataFields(level, values) {
  return SECTIONS.map((section) => {
    const fields = fieldsFor(level, section.key)
      .map((f) => {
        const name = `${section.key}.${f.key}`;
        return `<div class="field"><label for="${name}">${esc(f.ro)}</label>${fieldInput(name, f, values[name])}</div>`;
      })
      .join('');
    const extraName = `${section.key}.__extra`;
    return `<section><h2>${esc(section.ro)}</h2><div class="grid">${fields}</div>
      <div class="field"><label for="${extraName}">Alte câmpuri (câte unul pe rând, „Denumire câmp: valoare”)</label>
      <textarea id="${extraName}" name="${extraName}" placeholder="Exemplu: Certificare: IEC 62619">${esc(values[extraName] ?? '')}</textarea></div></section>`;
  }).join('');
}

export function modelFormPage({ user, model, values, errors }) {
  const isNew = !model;
  const categoryOptions = CATEGORIES.map(
    (c) => `<option value="${c}"${values.category === c ? ' selected' : ''}>${esc(CATEGORY_RO[c])}</option>`,
  ).join('');
  const head = isNew
    ? `<section class="grid"><div class="field"><label for="name">Denumirea modelului</label><input id="name" name="name" required maxlength="200" value="${esc(values.name ?? '')}"></div>
       <div class="field"><label for="category">Categorie</label><select id="category" name="category">${categoryOptions}</select></div></section>`
    : `<input type="hidden" name="expectedVersion" value="${model.current_version}">`;
  return layout({
    title: isNew ? 'Model nou' : `Editare model: ${model.name}`,
    user,
    errors,
    body: `<form class="stack" method="post" action="${isNew ? '/portal/models' : `/portal/models/${esc(model.id)}`}">
      ${head}
      <p class="hint">Completați ce este comun tuturor bateriilor acestui model. Câmpurile goale nu apar în pașaport.
      Lista de câmpuri este orientativă: verificați cerințele aplicabile din Regulamentul (UE) 2023/1542.</p>
      ${dataFields('model', values)}
      <div class="field"><label for="note">Notă pentru istoric (opțional)</label><input id="note" name="note" maxlength="1000" value="${esc(values.note ?? '')}"></div>
      <div class="row"><button type="submit">${isNew ? 'Creează modelul' : 'Salvează o versiune nouă'}</button>
      <a class="btn secondary" href="${isNew ? '/portal' : `/portal/models/${esc(model.id)}`}">Renunță</a></div></form>`,
  });
}

// ------------------------------------------------------------------ documents

const ACCESS_OPTIONS = () => Object.entries(ACCESS_RO).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('');

/** Bulk upload form: works without JavaScript; with it, uploads file by file with progress. */
function bulkUploadForm({ action, bulkUrl, maxBytes, label, hint }) {
  return `<form method="post" action="${action}" enctype="multipart/form-data" data-bulk-upload="${bulkUrl}" data-max-bytes="${maxBytes}" class="stack" style="margin-top:12px">
      <div class="field"><label>${esc(label)}</label>
        <div class="row"><input type="file" name="file" multiple accept=".pdf,.png,.jpg,.jpeg,.webp,.csv,.json,.txt">
        <span class="muted">sau un folder întreg:</span><input type="file" name="file" webkitdirectory multiple></div></div>
      <div class="row"><span class="muted">Acces</span>
        <select name="access">${ACCESS_OPTIONS()}</select><button type="submit">Încarcă fișierele</button></div>
      <progress hidden style="width:100%;margin-top:8px"></progress><p class="hint" data-status></p><ul class="errors-list" data-log style="color:var(--danger)"></ul>
      ${hint ? `<p class="hint">${hint}</p>` : ''}
    </form>`;
}

function documentsSection({ docs, uploadAction, removeBase, note, bulkUrl, maxBytes }) {
  const rows = docs.length
    ? docs
        .map(
          (d) => `<tr><td><a href="/portal/documents/${esc(d.id)}">${esc(d.name)}</a>${d.model_id && note ? ' <span class="muted">(din model)</span>' : ''}</td>
          <td>${esc(ACCESS_RO[d.access])}</td><td>${fmtSize(d.size)}</td>
          <td>${removeBase && (!d.model_id || !note) ? `<form method="post" action="${removeBase}/${esc(d.id)}/remove"><button class="link" type="submit">Ascunde</button></form>` : ''}</td></tr>`,
        )
        .join('')
    : '<tr><td colspan="4" class="muted">Niciun document.</td></tr>';
  return `<section><h2>Documente</h2>${note ? `<p class="hint">${esc(note)}</p>` : ''}
    <div class="table-wrap"><table><thead><tr><th>Fișier</th><th>Acces</th><th>Mărime</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    ${bulkUploadForm({ action: uploadAction, bulkUrl, maxBytes, label: 'Alegeți unul sau mai multe fișiere (PDF, imagini, CSV, JSON, text)' })}</section>`;
}

// ------------------------------------------------------------------ model page

function dataSummary(data) {
  return SECTIONS.map((s) => {
    const obj = data?.[s.key] ?? {};
    const keys = Object.keys(obj);
    const body = keys.length
      ? `<dl>${keys.map((k) => `<dt>${esc(fieldLabel(k, 'ro'))}</dt><dd>${esc(typeof obj[k] === 'string' ? obj[k] : JSON.stringify(obj[k]))}</dd>`).join('')}</dl>`
      : '<p class="muted">—</p>';
    return `<h3>${esc(s.ro)}</h3>${body}`;
  }).join('');
}

export function modelPage({ user, model, data, docs, passports, total, page, pageSize, flash, errors, bulkText, maxBytes }) {
  const rows = passports.length
    ? passports
        .map(
          (p) => `<tr><td><a href="/portal/passports/${esc(p.id)}">${esc(p.product_identifier)}</a></td>
          <td><a href="/p/${esc(p.id)}?lang=ro" target="_blank" rel="noopener">pagina publică</a></td>
          <td><a href="/portal/passports/${esc(p.id)}/qr.svg">QR</a></td><td>${esc(fmtDate(p.updated_at))}</td></tr>`,
        )
        .join('')
    : '<tr><td colspan="4" class="muted">Nu există încă baterii pentru acest model.</td></tr>';
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const base = `/portal/models/${esc(model.id)}`;
  const pager = pages > 1
    ? `<div class="pager">${page > 1 ? `<a href="${base}?page=${page - 1}">← Înapoi</a>` : ''}<span class="muted">Pagina ${page} din ${pages}</span>${page < pages ? `<a href="${base}?page=${page + 1}">Înainte →</a>` : ''}</div>`
    : '';
  return layout({
    title: model.name,
    user,
    flash,
    errors,
    body: `<section class="meta"><div><span>Categorie</span><strong>${esc(CATEGORY_RO[model.category])}</strong></div>
      <div><span>Versiune date</span><strong>v${model.current_version}</strong></div>
      <div><span>Baterii</span><strong>${total}</strong></div>
      <div><span>Actualizat</span><strong>${esc(fmtDate(model.updated_at))}</strong></div></section>

      <section><h2>Adaugă baterii</h2>
      <form method="post" action="${base}/passports" enctype="multipart/form-data">
        <div class="field"><label for="items">Câte un număr de serie (identificator) pe rând</label>
        <textarea id="items" name="items" placeholder="BAT-000001&#10;BAT-000002&#10;BAT-000003">${esc(bulkText ?? '')}</textarea></div>
        <div class="field"><label for="csv">sau un fișier CSV / Excel salvat ca CSV</label><input id="csv" type="file" name="csv" accept=".csv,.txt"></div>
        <p class="hint">CSV: prima coloană este identificatorul. Coloanele următoare, cu antet (de ex. <code>manufacturingDate</code>), devin date proprii fiecărei baterii.
        O coloană <code>externalUrl</code> cu adresa pașaportului găzduit de producător face ca bateria să fie găzduită extern, cu copie de siguranță în UE. Maximum 5.000 de rânduri odată.</p>
        <button type="submit">Creează pașapoartele</button></form></section>

      <section><div class="row" style="justify-content:space-between"><h2>Baterii (${total})</h2>
      <a class="btn secondary" href="${base}/passports.csv">Descarcă CSV cu adresele QR</a></div>
      <p class="hint">Fișierul CSV conține pentru fiecare baterie adresa care trebuie codificată în QR, gata pentru programul de etichete.</p>
      <div class="table-wrap"><table><thead><tr><th>Identificator</th><th>Pașaport</th><th>Cod QR</th><th>Actualizat</th></tr></thead><tbody>${rows}</tbody></table></div>${pager}</section>

      ${documentsSection({ docs, uploadAction: `${base}/documents`, removeBase: `${base}/documents`, bulkUrl: `/portal/upload?target=model&id=${esc(model.id)}`, maxBytes, note: 'Documentele modelului apar pe pașaportul fiecărei baterii din acest model și sunt stocate o singură dată.' })}

      <section><h2>Documente per baterie (în bulk)</h2>
      <p class="hint">Selectați oricâte fișiere sau un folder întreg. Fiecare fișier ajunge automat la bateria al cărei număr de serie apare la începutul numelui:
      <code>BAT-0001.pdf</code>, <code>BAT-0001_raport-test.pdf</code> sau <code>BAT-0001 certificat.pdf</code> → bateria <code>BAT-0001</code>.
      Fișierele care nu corespund niciunei baterii din acest model sunt raportate și nu se încarcă.</p>
      ${bulkUploadForm({ action: `${base}/battery-documents`, bulkUrl: `/portal/upload?target=battery&id=${esc(model.id)}`, maxBytes, label: 'Fișiere pentru bateriile acestui model' })}</section>

      <section><div class="row" style="justify-content:space-between"><h2>Date comune ale modelului</h2>
      <a class="btn secondary" href="${base}/edit">Editează</a></div>${dataSummary(data)}</section>`,
  });
}

// ------------------------------------------------------------------ passport page

const MIRROR_STATUS = { ok: 'Funcțional', down: 'Căzut — vizitatorii văd copia din UE', unchecked: 'Neverificat încă' };

function externalSection(passport, events) {
  const base = `/portal/passports/${esc(passport.id)}`;
  if (!passport.external_url) {
    return `<section><h2>Găzduire externă (opțional)</h2>
      <p class="hint">Dacă producătorul (de exemplu, fabrica din China) găzduiește deja pașaportul, introduceți adresa lui.
      Codul QR rămâne pe domeniul acestei platforme: vizitatorii sunt trimiși la producător cât timp serverul lui funcționează,
      iar dacă acesta cade, văd automat copia arhivată în UE. Răspunderea pentru disponibilitate rămâne a importatorului.</p>
      <form method="post" action="${base}/external"><input name="externalUrl" type="url" placeholder="https://passport.producator.cn/..." required>
      <button type="submit">Salvează și verifică</button></form></section>`;
  }
  const status = passport.mirror_status ?? 'unchecked';
  const rows = events.map((e) => `<tr><td>${esc(fmtDate(e.at))}</td><td>${esc(e.status === 'ok' ? 'funcțional' : 'căzut')}</td>
    <td>${e.sha256 ? 'copie nouă' : esc(e.error ?? '')}</td></tr>`).join('');
  return `<section><h2>Găzduire externă și copia din UE</h2>
    <section class="meta" style="border:0;padding:0">
      <div><span>Server extern</span><strong style="color:${status === 'down' ? 'var(--danger)' : 'inherit'}">${esc(MIRROR_STATUS[status])}</strong></div>
      <div><span>Ultima verificare</span><strong>${esc(fmtDate(passport.mirror_checked_at)) || '—'}</strong></div>
      <div><span>Ultima copie arhivată</span><strong>${esc(fmtDate(passport.mirror_fetched_at)) || '—'}</strong></div>
      <div style="grid-column:1/-1"><span>Adresa externă</span><a class="mono" href="${esc(passport.external_url)}" target="_blank" rel="noopener noreferrer">${esc(passport.external_url)}</a></div>
    </section>
    ${passport.mirror_error ? `<p class="hint" style="color:var(--danger)">Ultima eroare: ${esc(passport.mirror_error)}</p>` : ''}
    <div class="row">
      <form method="post" action="${base}/mirror/check"><button type="submit">Verifică acum</button></form>
      ${passport.mirror_sha256 ? `<a class="btn secondary" href="/p/${esc(passport.id)}?mirror=1&lang=ro" target="_blank" rel="noopener">Vezi copia din UE</a>` : ''}
      <form method="post" action="${base}/external"><input type="hidden" name="externalUrl" value=""><button class="secondary" type="submit">Găzduiește pe platformă</button></form>
    </div>
    <p class="hint">Verificarea automată rulează zilnic. Se păstrează un istoric al schimbărilor de stare și al copiilor noi.</p>
    ${rows ? `<div class="table-wrap"><table><thead><tr><th>Data</th><th>Stare</th><th>Detalii</th></tr></thead><tbody>${rows}</tbody></table></div>` : ''}
  </section>`;
}

export function accountPage({ user, error, flash }) {
  return layout({
    title: 'Contul meu',
    user,
    flash,
    errors: error ? [error] : [],
    body: `<section><p>Cont: <strong>${esc(user.email)}</strong> · ${esc(user.tenantName)}</p>
      <form class="stack" method="post" action="/portal/account">
      <div class="field"><label for="current">Parola actuală</label><input id="current" name="current" type="password" autocomplete="current-password" required></div>
      <div class="field"><label for="p1">Parola nouă (minimum 10 caractere)</label><input id="p1" name="password" type="password" autocomplete="new-password" minlength="10" required></div>
      <div class="field"><label for="p2">Repetați parola nouă</label><input id="p2" name="password2" type="password" autocomplete="new-password" minlength="10" required></div>
      <button type="submit">Schimbă parola</button></form>
      <p class="hint">După schimbare, celelalte sesiuni deschise ale contului sunt închise.</p></section>`,
  });
}

export function passportPage({ user, passport, model, values, effective, docs, versions, qrSvg, publicUrl, mirrorEvents = [], flash, errors, maxBytes }) {
  const versionRows = versions
    .slice()
    .reverse()
    .map((v) => `<tr><td>v${v.version}</td><td>${esc(fmtDate(v.created_at))}</td><td>${esc(v.note ?? '')}</td></tr>`)
    .join('');
  return layout({
    title: `Pașaport ${passport.product_identifier}`,
    user,
    flash,
    errors,
    body: `<section class="row" style="align-items:flex-start;gap:24px">
        <div class="qr">${qrSvg}</div>
        <div><p><span class="muted">Adresa din codul QR:</span><br><a href="${esc(publicUrl)}?lang=ro" target="_blank" rel="noopener">${esc(publicUrl)}</a></p>
        <p><span class="muted">Model:</span> ${model ? `<a href="/portal/models/${esc(model.id)}">${esc(model.name)}</a>` : '—'}</p>
        <div class="row"><a class="btn secondary" href="/portal/passports/${esc(passport.id)}/qr.svg">Descarcă QR (SVG)</a>
        <a class="btn secondary" href="${esc(publicUrl)}?lang=ro" target="_blank" rel="noopener">Vezi pagina publică</a></div></div></section>

      ${externalSection(passport, mirrorEvents)}

      <form class="stack" method="post" action="/portal/passports/${esc(passport.id)}">
        <input type="hidden" name="expectedVersion" value="${passport.current_version}">
        <p class="hint">Aici completați doar ce este specific acestei baterii. Ce completați aici are prioritate față de datele modelului.</p>
        ${dataFields('item', values)}
        <div class="field"><label for="note">Notă pentru istoric (opțional)</label><input id="note" name="note" maxlength="1000"></div>
        <button type="submit">Salvează o versiune nouă</button></form>

      ${documentsSection({ docs, uploadAction: `/portal/passports/${esc(passport.id)}/documents`, removeBase: `/portal/passports/${esc(passport.id)}/documents`, bulkUrl: `/portal/upload?target=passport&id=${esc(passport.id)}`, maxBytes, note: model ? 'Documentele marcate „din model” se gestionează din pagina modelului.' : '' })}

      <section><h2>Datele afișate în pașaport (model + baterie)</h2>${dataSummary(effective)}</section>
      <section><h2>Istoric versiuni</h2><div class="table-wrap"><table><thead><tr><th>Versiune</th><th>Data</th><th>Notă</th></tr></thead><tbody>${versionRows}</tbody></table></div></section>`,
  });
}
