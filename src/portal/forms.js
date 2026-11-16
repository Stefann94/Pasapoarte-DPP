import { fieldsFor, SECTIONS } from '../fields.js';
import { badRequest, readBody } from '../http.js';
import { MAX_BULK } from '../passports.js';

const EXTRA = '__extra';
const MAX_KEY = 100;

function convert(field, raw) {
  const value = raw.trim();
  if (field.type === 'number' && /^-?\d+([.,]\d+)?$/.test(value)) return Number(value.replace(',', '.'));
  return value;
}

/**
 * Converts the portal form into passport data. Each section has the known
 * fields for the given level plus a free "Key: value" textarea for anything else.
 */
export function formToData(form, level) {
  const data = {};
  const errors = [];
  for (const section of SECTIONS) {
    const out = {};
    for (const field of fieldsFor(level, section.key)) {
      const raw = form.get(`${section.key}.${field.key}`);
      if (typeof raw === 'string' && raw.trim()) out[field.key] = convert(field, raw);
    }
    const extra = form.get(`${section.key}.${EXTRA}`);
    if (typeof extra === 'string') {
      extra.split(/\r?\n/).forEach((line, i) => {
        if (!line.trim()) return;
        const idx = line.indexOf(':');
        const key = idx > 0 ? line.slice(0, idx).trim() : '';
        if (!key || key.length > MAX_KEY) {
          errors.push(`${section.ro}, rândul ${i + 1}: folosiți formatul „Denumire câmp: valoare”.`);
          return;
        }
        out[key] = parseExtraValue(line.slice(idx + 1).trim());
      });
    }
    data[section.key] = out;
  }
  return { data, errors };
}

function parseExtraValue(v) {
  if (/^[[{"]/.test(v)) {
    try {
      return JSON.parse(v);
    } catch {
      /* plain text */
    }
  }
  return v;
}

const extraValueText = (v) =>
  typeof v === 'string' && !/[\r\n]/.test(v) && !/^[[{"]/.test(v) ? v : JSON.stringify(v);

/** Inverse of formToData: values for the form fields, unknown keys in the extra textarea. */
export function dataToForm(data, level) {
  const values = {};
  for (const section of SECTIONS) {
    const known = new Set(fieldsFor(level, section.key).map((f) => f.key));
    const obj = data?.[section.key] ?? {};
    const extras = [];
    for (const [k, v] of Object.entries(obj)) {
      if (known.has(k)) values[`${section.key}.${k}`] = typeof v === 'string' ? v : String(v);
      else extras.push(`${k}: ${extraValueText(v)}`);
    }
    values[`${section.key}.${EXTRA}`] = extras.join('\n');
  }
  return values;
}

export const formValues = (form) => Object.fromEntries([...form.entries()].filter(([, v]) => typeof v === 'string'));

/** Parses multipart/form-data (file uploads) with the platform's built-in parser. */
export async function readMultipart(req, limit) {
  const type = req.headers['content-type'] ?? '';
  if (!type.startsWith('multipart/form-data')) throw badRequest('Expected multipart/form-data');
  const buf = await readBody(req, limit);
  try {
    return await new Response(buf, { headers: { 'content-type': type } }).formData();
  } catch {
    throw badRequest('Malformed form upload');
  }
}

/** Minimal CSV parser: quotes, "" escapes, comma or semicolon (Excel RO) delimiter. */
export function parseCsv(text) {
  const clean = text.replace(/^﻿/, '');
  const firstLine = clean.split(/\r?\n/, 1)[0] ?? '';
  const delim = firstLine.includes(';') && !firstLine.includes(',') ? ';' : firstLine.includes('\t') && !firstLine.includes(',') ? '\t' : ',';
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i];
    if (quoted) {
      if (c === '"' && clean[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === delim) {
      row.push(cell);
      cell = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && clean[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else cell += c;
  }
  if (cell !== '' || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows.map((r) => r.map((x) => x.trim())).filter((r) => r.some((x) => x !== ''));
}

const HEADER_RE = /^(productidentifier|identificator|serial|serie|număr|numar|nr\.?|id|serialnumber|sn)$/i;

/**
 * Turns pasted text or a CSV file into bulk items. One identifier per line, or
 * a CSV whose first column is the identifier and whose header names further
 * per-battery fields (e.g. manufacturingDate).
 */
export function itemsFromCsv(text) {
  const rows = parseCsv(text);
  if (!rows.length) throw badRequest('Lista de baterii este goală.');
  const hasHeader = rows[0].length > 1 || HEADER_RE.test(rows[0][0].replace(/\s+/g, ''));
  const header = hasHeader ? rows[0] : null;
  const body = hasHeader ? rows.slice(1) : rows;
  if (!body.length) throw badRequest('Lista de baterii este goală.');
  if (body.length > MAX_BULK) throw badRequest(`Maximum ${MAX_BULK} baterii odată.`);
  return body.map((r) => {
    const item = { productIdentifier: r[0] };
    if (header && r.length > 1) {
      const pub = {};
      header.slice(1).forEach((h, i) => {
        const v = r[i + 1];
        if (h && v) pub[h] = v;
      });
      if (Object.keys(pub).length) item.data = { public: pub };
    }
    return item;
  });
}

export function csvEscape(value) {
  const s = String(value ?? '');
  return /[",;\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
