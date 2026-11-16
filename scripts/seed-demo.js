// Creates a demo client, a sample battery passport and two restricted-access
// tokens on a running server, then prints the URLs to open.
// Usage: npm start (in one terminal), then: npm run demo

const base = (process.env.BASE_URL ?? `http://localhost:${process.env.PORT ?? 3000}`).replace(/\/+$/, '');
const admin = process.env.ADMIN_TOKEN;
if (!admin) throw new Error('ADMIN_TOKEN is not set (create .env from .env.example)');

async function call(method, path, token, body) {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${JSON.stringify(data)}`);
  return data;
}

const { apiKey } = await call('POST', '/admin/tenants', admin, { name: 'Demo Importer SRL', vatId: 'RO00000000' });
const passport = await call('POST', '/api/passports', apiKey.token, {
  productIdentifier: `DEMO-${Date.now()}`,
  category: 'industrial',
  note: 'demo data',
  data: {
    public: {
      manufacturer: { name: 'Demo Cells GmbH', address: 'Example Str. 1, Berlin, DE' },
      manufacturingDate: '2027-01-15',
      batteryModel: 'DC-STOR-100',
      batteryCategory: 'Industrial battery for stationary energy storage',
      weightKg: 610,
      chemistry: 'LFP (lithium iron phosphate)',
      ratedCapacityKWh: 100,
      expectedLifetimeCycles: 6000,
      hazardousSubstances: ['none above thresholds'],
      euDeclarationOfConformity: 'https://example.com/doc/DC-STOR-100.pdf',
    },
    legitimateInterest: {
      dismantlingInformation: 'See service manual chapter 7; disconnect HV before opening.',
      partNumbersForSpareParts: ['DC-MOD-12', 'DC-BMS-3'],
    },
    authorities: {
      testReports: ['IEC 62619 report no. 2027-0042'],
    },
  },
});
const legit = await call('POST', '/admin/accessors', admin, { name: 'Demo Recycler', role: 'legitimate_interest' });
const authority = await call('POST', '/admin/accessors', admin, { name: 'Demo Market Surveillance', role: 'authority' });

console.log(`
Passport page (open in a browser): ${passport.url}?lang=ro
JSON:                              ${passport.url}?format=json

Client API key:                    ${apiKey.token}
Legitimate-interest token:         ${legit.token}
Authority token:                   ${authority.token}
`);
