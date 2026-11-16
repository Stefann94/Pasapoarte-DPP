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
  document_removed: 'Documentul a fost ascuns.',
  password_set: 'Parola a fost setată. Vă puteți autentifica.',
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

function layout({ title, user, body, flash, errors }) {
  const nav = user
    ? `<nav class="top"><a class="brand" href="/portal">Pașapoarte DPP · ${esc(user.tenantName)}</a>
        <a href="/portal">Modele</a><a href="/portal/export">Export</a>
        <form method="post" action="/portal/logout"><button class="link" type="submit">Ieșire</button></form></nav>`
    : `<nav class="top"><span class="brand">Pașapoarte DPP · Portal clienți</span></nav>`;
  const flashHtml = flash && FLASH[flash] ? `<div class="flash">${esc(FLASH[flash])}</div>` : '';
  const errorHtml = errors?.length ? `<div class="errors">${errors.map((e) => `<div>${esc(e)}</div>`).join('')}</div>` : '';
  const suspended = user && user.status !== 'active'
    ? '<div class="errors">Contul este suspendat: pașapoartele rămân publice, dar modificările sunt blocate.</div>'
    : '';
  return `<!doctype html>
<html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · Pașapoarte DPP</title><style>${CSS}</style></head>
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

export function dashboardPage({ user, models, recent, totalPassports, flash }) {
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
      <div><span class="muted">Pașapoarte</span><strong>${totalPassports}</strong></div></div>
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

function documentsSection({ docs, uploadAction, removeBase, note }) {
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
    <form method="post" action="${uploadAction}" enctype="multipart/form-data" style="margin-top:12px">
      <input type="file" name="file" required accept=".pdf,.png,.jpg,.jpeg,.webp,.csv,.json,.txt">
      <select name="access">${Object.entries(ACCESS_RO).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('')}</select>
      <button type="submit">Încarcă</button></form>
    <p class="hint">PDF, imagini, CSV, JSON sau text.</p></section>`;
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

export function modelPage({ user, model, data, docs, passports, total, page, pageSize, flash, errors, bulkText }) {
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
        <p class="hint">CSV: prima coloană este identificatorul. Coloanele următoare, cu antet (de ex. <code>manufacturingDate</code>), devin date proprii fiecărei baterii. Maximum 5.000 de rânduri odată.</p>
        <button type="submit">Creează pașapoartele</button></form></section>

      <section><div class="row" style="justify-content:space-between"><h2>Baterii (${total})</h2>
      <a class="btn secondary" href="${base}/passports.csv">Descarcă CSV cu adresele QR</a></div>
      <p class="hint">Fișierul CSV conține pentru fiecare baterie adresa care trebuie codificată în QR, gata pentru programul de etichete.</p>
      <div class="table-wrap"><table><thead><tr><th>Identificator</th><th>Pașaport</th><th>Cod QR</th><th>Actualizat</th></tr></thead><tbody>${rows}</tbody></table></div>${pager}</section>

      ${documentsSection({ docs, uploadAction: `${base}/documents`, removeBase: `${base}/documents`, note: 'Documentele modelului apar pe pașaportul fiecărei baterii din acest model și sunt stocate o singură dată.' })}

      <section><div class="row" style="justify-content:space-between"><h2>Date comune ale modelului</h2>
      <a class="btn secondary" href="${base}/edit">Editează</a></div>${dataSummary(data)}</section>`,
  });
}

// ------------------------------------------------------------------ passport page

export function passportPage({ user, passport, model, values, effective, docs, versions, qrSvg, publicUrl, flash, errors }) {
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

      <form class="stack" method="post" action="/portal/passports/${esc(passport.id)}">
        <input type="hidden" name="expectedVersion" value="${passport.current_version}">
        <p class="hint">Aici completați doar ce este specific acestei baterii. Ce completați aici are prioritate față de datele modelului.</p>
        ${dataFields('item', values)}
        <div class="field"><label for="note">Notă pentru istoric (opțional)</label><input id="note" name="note" maxlength="1000"></div>
        <button type="submit">Salvează o versiune nouă</button></form>

      ${documentsSection({ docs, uploadAction: `/portal/passports/${esc(passport.id)}/documents`, removeBase: `/portal/passports/${esc(passport.id)}/documents`, note: model ? 'Documentele marcate „din model” se gestionează din pagina modelului.' : '' })}

      <section><h2>Datele afișate în pașaport (model + baterie)</h2>${dataSummary(effective)}</section>
      <section><h2>Istoric versiuni</h2><div class="table-wrap"><table><thead><tr><th>Versiune</th><th>Data</th><th>Notă</th></tr></thead><tbody>${versionRows}</tbody></table></div></section>`,
  });
}
