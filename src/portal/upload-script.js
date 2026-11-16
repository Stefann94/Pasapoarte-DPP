/*
 * Browser script for bulk upload forms (served at /portal/assets/upload.js).
 * Sends one file per request, three at a time, with progress and a per-file
 * error list. Without JavaScript the forms still post all files at once.
 */
export const UPLOAD_SCRIPT_SOURCE = String.raw`(() => {
  'use strict';
  const CONCURRENCY = 3;
  const TYPES = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', json: 'application/json', csv: 'text/csv', txt: 'text/plain' };
  const typeOf = (f) => TYPES[(f.name.split('.').pop() || '').toLowerCase()] || f.type || 'application/octet-stream';

  for (const form of document.querySelectorAll('form[data-bulk-upload]')) {
    const inputs = [...form.querySelectorAll('input[type=file]')];
    const button = form.querySelector('button[type=submit]');
    const progress = form.querySelector('progress');
    const status = form.querySelector('[data-status]');
    const log = form.querySelector('[data-log]');
    const maxBytes = Number(form.dataset.maxBytes || 0);

    // Picking a folder or a file list both feed the same upload.
    for (const input of inputs) {
      input.addEventListener('change', () => {
        const n = inputs.reduce((sum, i) => sum + i.files.length, 0);
        status.textContent = n ? n + ' fișiere selectate' : '';
      });
    }

    form.addEventListener('submit', async (event) => {
      const files = inputs.flatMap((i) => [...i.files]).filter((f) => !f.name.startsWith('.'));
      if (!files.length) return;
      event.preventDefault();
      const access = (form.querySelector('[name=access]') || {}).value || 'public';
      button.disabled = true;
      progress.hidden = false;
      progress.max = files.length;
      progress.value = 0;
      log.textContent = '';
      let ok = 0;
      const failed = [];
      const queue = files.slice();

      const addError = (name, message) => {
        failed.push(name);
        const li = document.createElement('li');
        li.textContent = name + ': ' + message;
        log.appendChild(li);
      };

      const worker = async () => {
        while (queue.length) {
          const file = queue.shift();
          if (maxBytes && file.size > maxBytes) {
            addError(file.name, 'depășește ' + Math.round(maxBytes / 1048576) + ' MB');
          } else {
            try {
              const url = form.dataset.bulkUpload + '&access=' + encodeURIComponent(access) + '&name=' + encodeURIComponent(file.name);
              const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': typeOf(file) }, body: file, credentials: 'same-origin' });
              const body = await res.json().catch(() => ({ message: 'răspuns invalid (' + res.status + ')' }));
              if (res.ok) ok++;
              else addError(file.name, body.message || 'eroare ' + res.status);
            } catch (err) {
              addError(file.name, 'conexiune întreruptă');
            }
          }
          progress.value += 1;
          status.textContent = progress.value + ' / ' + files.length + ' procesate · ' + ok + ' încărcate' + (failed.length ? ' · ' + failed.length + ' cu erori' : '');
        }
      };
      await Promise.all(Array.from({ length: Math.min(CONCURRENCY, files.length) }, worker));

      button.disabled = false;
      for (const i of inputs) i.value = '';
      status.textContent = 'Gata: ' + ok + ' din ' + files.length + ' fișiere încărcate' + (failed.length ? ', ' + failed.length + ' cu erori (lista de mai jos).' : '.');
      if (!failed.length) {
        const a = document.createElement('a');
        a.href = location.pathname + '?msg=documents_added';
        a.textContent = ' Reîncarcă pagina';
        status.appendChild(a);
      }
    });
  }
})();
`;
