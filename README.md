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

- **Cache de pașapoarte în memorie.** La prima accesare, pașaportul, versiunea curentă și documentele vin dintr-o **singură** interogare. Timp de 2 secunde, accesările următoare nu mai ating deloc baza de date. După aceea ajunge o verificare minusculă a reviziei. Modificările invalidează imediat cache-ul.
- **Răspunsuri pre-randate și pre-comprimate** (brotli/gzip), păstrate în cache.
- **ETag + 304** pentru browsere. Pe Vercel, `s-maxage` permite rețelei CDN să servească scanările repetate fără să mai pornească funcția.
- Funcția Vercel rulează în **Frankfurt (fra1)**, lângă baza Supabase din aceeași regiune.
- Documentele sunt trimise în **stream**. Hash-ul SHA-256 servește drept ETag.

Măsurat cu `npm run bench` (laptop, un singur proces, clientul de test în același proces): **~2.100–2.700 cereri/s, p50 ≈ 17–19 ms la 50 de conexiuni simultane**.

## Pornire locală

Necesită Node.js ≥ 22. Local nu aveți nevoie de Supabase: dacă `DATABASE_URL` lipsește, aplicația folosește automat PGlite, un PostgreSQL real care rulează în proces, cu datele salvate în `data/`.

```powershell
npm install
copy .env.example .env      # apoi editați ADMIN_TOKEN
npm start                   # http://localhost:3000
npm run demo                # (alt terminal) creează un client și un pașaport demo
npm test
npm run bench
```

## Publicare pe Vercel + Supabase

1. **Supabase**: creați un proiect în regiunea **Central EU (Frankfurt)**.
2. Din Supabase, copiați:
   - *Project Settings → Database → Connection string → **Transaction pooler*** (portul 6543) → `DATABASE_URL`
   - *Project Settings → API* → `SUPABASE_URL` și cheia **service_role** → `SUPABASE_SERVICE_ROLE_KEY` (secretă; nu ajunge niciodată în browser)
3. Local, puneți aceste valori în `.env` și rulați **o singură dată** `npm run migrate`. Scriptul creează tabelele (în schema `dpp`, neexpusă de API-ul Supabase) și bucket-ul privat `dpp-documents`.
4. **Vercel**: *Project → Settings → Environment Variables*. Adăugați `ADMIN_TOKEN`, `DATABASE_URL`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` (opțional `BASE_URL`), apoi *Redeploy*.
5. Verificați `https://<proiect>.vercel.app/healthz`, care trebuie să răspundă `{"status":"ok","database":"postgres","storage":"supabase"}`.

Limită Vercel: cererile pot avea maximum 4,5 MB, deci documentele sunt limitate la 4 MB. Pentru fișiere mai mari, pasul următor este încărcarea directă în Supabase Storage prin URL semnat.

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
  index.js        pornire server local
  app.js          server HTTP, gestionarea erorilor, rate limit
  config.js       configurare din variabile de mediu
  db.js           adaptoare PostgreSQL (pg / PGlite) + toate interogările
  schema.sql      schema bazei de date (schema "dpp")
  passports.js    validare, versiuni, cache de snapshot, vizualizare pe niveluri
  portability.js  export/import
  audit.js        jurnal înlănțuit
  blobstore.js    documente: Supabase Storage sau disc local, adresate prin SHA-256
  auth.js         chei API, tokenuri de acces, sesiuni
  http.js         router, compresie, ETag, utilitare
  views.js        HTML public (RO/EN)
  routes/         admin, tenant (client), public
api/index.js      punctul de intrare pentru Vercel
vercel.json       rutare, regiune fra1
test/             teste cap-coadă (node:test, pe PGlite)
scripts/          migrare Supabase, demo, benchmark
```

## Ce lipsește până la producție

MVP-ul demonstrează fluxul complet, dar înainte de clienți reali trebuie făcute următoarele:

1. **Backup Supabase**: activați Point-in-Time Recovery (planul Pro) și testați periodic o restaurare.
2. **Domeniu stabil pe termen lung** pentru `BASE_URL`. Adresa `*.vercel.app` nu trebuie tipărită pe etichete.
3. **Documente mai mari de 4 MB**: încărcare directă în Storage prin URL semnat.
4. **Monitorizare și alerte** (disponibilitate, erori).
5. **Procedură de verificare a organizațiilor** care primesc acces restricționat, ajustată când Comisia finalizează regulile de acces.
6. **Integrarea cu registrul UE**, dacă preluați și înregistrarea în numele clienților.
7. **Ancorarea externă a jurnalului de audit** (publicarea periodică a ultimului hash în afara bazei de date).
8. Contracte (rolul de găzduire, SLA, export la încetare, continuitate), GDPR, test de penetrare, apoi ISO/IEC 27001.

> Platforma verifică structura datelor, nu certifică adevărul lor. Responsabilitatea pentru conținutul pașaportului rămâne la operatorul economic.
