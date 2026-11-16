# Pașapoarte DPP: găzduire pentru pașapoarte digitale ale bateriilor

MVP pentru un serviciu de **găzduire** a pașapoartelor digitale de produs (DPP) pentru baterii, conform Regulamentului (UE) 2023/1542 (pașaportul bateriei este obligatoriu de la **18 februarie 2027** pentru bateriile VE, LMT și industriale > 2 kWh).

Platforma **nu generează** conținutul pașapoartelor. Îl primește de la operatorul economic sau de la platforma care l-a generat, îl publică la o adresă stabilă (cea din codul QR), controlează accesul pe niveluri, păstrează istoricul și permite oricând exportul complet.

## Ce face

| Funcție | Detalii |
|---|---|
| Adresă permanentă | `https://<domeniu>/p/<id>`, adresa la care trimite codul QR. Id-ul poate fi furnizat de client (util la migrare). |
| 3 niveluri de acces | `public`, `legitimate_interest` (reciclatori, reparatori etc.), `authority` (organisme notificate, supraveghere piață, Comisie), conform art. 77(2) și anexei XIII. |
| Pagină publică | HTML server-side, fără JavaScript, optimizată pentru telefon, RO/EN, temă luminoasă/întunecată. Aceeași adresă întoarce JSON cu `?format=json` sau `Accept: application/json`. |
| Versiuni imuabile | Fiecare actualizare creează o versiune nouă; versiunile vechi nu pot fi modificate sau șterse (trigger în baza de date). Concurență optimistă prin `expectedVersion`. |
| Documente | PDF/PNG/JPEG/WebP/JSON/CSV/TXT, cu nivel de acces per document, verificarea tipului real al fișierului și stocare adresată prin SHA-256. |
| Jurnal de audit | Doar adăugare (append-only), înlănțuit criptografic (hash chain), cu verificare prin `/admin/audit/verify`. |
| Portabilitate | Export complet (versiuni + documente) și import pe altă instanță, cu verificarea integrității. Id-urile se păstrează, deci QR-urile rămân valide. |
| Continuitate | Un client suspendat (de ex. neplată) **nu dispare public**. Doar modificările sunt blocate, iar exportul rămâne disponibil. |
| Securitate | Tokenuri stocate doar ca hash, CSP strict, cookie de sesiune HttpOnly/Secure/SameSite, fișierele încărcate nu rulează niciodată ca HTML, limitare de rată. |

## Performanță

Calea critică este scanarea QR (`GET /p/:id`), așa că acolo e optimizată:

- **Cache de snapshot per revizie**: o singură căutare după cheia primară per cerere. Fără parsare JSON și fără join-uri. Rămâne corect și cu mai multe procese pe aceeași bază.
- **Răspunsuri pre-randate și pre-comprimate** (brotli/gzip), păstrate în cache.
- **ETag + 304**: un browser care revine nu mai descarcă pagina.
- Toate interogările SQL sunt **pregătite o singură dată** la pornire. SQLite rulează în WAL, cu cache mare.
- Documentele sunt trimise în **stream**, fără să fie încărcate în memorie. Hash-ul SHA-256 servește drept ETag.
- **Zero dependențe npm**: pornire instantanee, nimic de instalat sau de actualizat.

Măsurat cu `node scripts/bench.js` (laptop, un singur proces Node, clientul de test rulând în același proces): **~2.000–2.400 cereri/s, p50 ≈ 20 ms la 50 de conexiuni simultane**.

## Pornire rapidă

Necesită Node.js ≥ 24 (testat pe Node 26). Nu e nevoie de `npm install`.

```powershell
copy .env.example .env      # apoi editați ADMIN_TOKEN
npm start                   # pornește serverul pe http://localhost:3000
npm run demo                # (alt terminal) creează un client și un pașaport demo
npm test                    # rulează testele
node scripts/bench.js       # benchmark
```

`npm run demo` afișează adresa pașaportului și tokenurile pentru accesul restricționat. Deschideți adresa în browser și introduceți un token în secțiunea „Acces restricționat”.

## API

Autentificare: `Authorization: Bearer <token>`.

**Administrator platformă** (`ADMIN_TOKEN`)

| Metodă | Cale | Rol |
|---|---|---|
| POST | `/admin/tenants` `{name, vatId?}` | creează un client și întoarce cheia API |
| GET | `/admin/tenants` | listă clienți |
| POST | `/admin/tenants/:id/api-keys` | cheie API nouă |
| POST | `/admin/api-keys/:id/revoke` | revocă o cheie |
| POST | `/admin/tenants/:id/suspend` / `reactivate` | suspendă sau reactivează modificările |
| POST | `/admin/accessors` `{name, role}` | creează un token de acces restricționat (`legitimate_interest` / `authority`), după verificarea organizației |
| POST | `/admin/accessors/:id/revoke` | revocă tokenul și închide sesiunile |
| GET | `/admin/audit`, `/admin/audit/verify` | jurnal de audit și verificarea lanțului |

**Client** (cheie `dpk_...`)

| Metodă | Cale | Rol |
|---|---|---|
| POST | `/api/passports` | creează: `{id?, productIdentifier, category: ev\|lmt\|industrial, data: {public, legitimateInterest?, authorities?}, note?}` |
| GET | `/api/passports?limit&offset` | listă |
| GET | `/api/passports/:id` | date curente, istoricul versiunilor, documente |
| PUT | `/api/passports/:id` | versiune nouă: `{data, note?, expectedVersion?}` |
| GET | `/api/passports/:id/versions/:n` | o versiune anterioară |
| POST | `/api/passports/:id/documents?name=...&access=...` | upload: corpul cererii este fișierul, iar `Content-Type` este tipul lui |
| DELETE | `/api/passports/:id/documents/:docId` | ascunde documentul (fișierul rămâne pentru istoric) |
| GET | `/api/export?includeDocuments=1` | export complet |
| POST | `/api/import` | import din export |

**Public**

| Metodă | Cale | Rol |
|---|---|---|
| GET | `/p/:id` | pagina pașaportului (HTML sau JSON); cu token `dpa_...` sau sesiune vede și nivelurile restricționate |
| GET | `/p/:id/documents/:docId` | document, dacă nivelul de acces permite |
| POST | `/p/:id/access`, `/p/:id/logout` | autentificare/ieșire din browser cu token |
| GET | `/healthz` | verificare stare |

Exemplu PowerShell:

```powershell
$h = @{ Authorization = "Bearer dpk_..." }
$body = @{ productIdentifier = "BAT-0001"; category = "industrial";
           data = @{ public = @{ batteryModel = "X-100"; chemistry = "LFP" } } } | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Post -Uri http://localhost:3000/api/passports -Headers $h -Body $body -ContentType "application/json"
```

## Arhitectură

```
src/
  index.js        pornire server
  app.js          server HTTP, gestionarea erorilor, rate limit
  config.js       configurare din variabile de mediu
  db.js           schema SQLite + toate interogările (prepared statements)
  passports.js    validare, versiuni, cache de snapshot, vizualizare pe niveluri
  portability.js  export/import
  audit.js        jurnal înlănțuit
  blobstore.js    stocare documente adresată prin conținut
  auth.js         chei API, tokenuri de acces, sesiuni
  http.js         router, compresie, ETag, utilitare
  views.js        HTML public (RO/EN)
  routes/         admin, tenant (client), public
test/             teste cap-coadă (node:test)
scripts/          demo și benchmark
```

## Ce lipsește până la producție

MVP-ul demonstrează fluxul complet, dar înainte de clienți reali trebuie făcute următoarele:

1. **Bază de date administrată.** Mutare de pe SQLite pe PostgreSQL administrat într-o regiune UE (de ex. **Supabase**, regiunea Frankfurt), cu backup automat și restaurare la un moment anterior (PITR). Toate interogările sunt deja grupate în `src/db.js`.
2. **Stocare documente în object storage** (Supabase Storage, S3 sau compatibil), cu backup separat. Interfața `blobstore.js` rămâne aceeași.
3. **Domeniu stabil pe termen lung** pentru `BASE_URL`, plus TLS și un reverse proxy/CDN în față.
4. **Monitorizare și alerte** (disponibilitate, erori), plus teste periodice de restaurare.
5. **Procedură de verificare a organizațiilor** care primesc acces restricționat, ajustată când Comisia finalizează regulile de acces.
6. **Integrarea cu registrul UE**, dacă preluați și înregistrarea în numele clienților.
7. **Ancorarea externă a jurnalului de audit** (publicarea periodică a ultimului hash în afara bazei de date).
8. Contracte (rolul de găzduire, SLA, export la încetare, continuitate), GDPR, test de penetrare, apoi ISO/IEC 27001.

> Platforma verifică structura datelor, nu certifică adevărul lor. Responsabilitatea pentru conținutul pașaportului rămâne la operatorul economic.
