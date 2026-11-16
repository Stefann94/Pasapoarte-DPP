import { loadConfig } from './config.js';
import { createApp } from './app.js';

const config = loadConfig();
const app = await createApp(config);

app.server.listen(config.port, () => {
  const db = config.databaseUrl ? 'PostgreSQL (DATABASE_URL)' : `local PGlite in ${config.pgliteDir}`;
  console.log(`DPP hosting listening on port ${config.port} — public base URL ${config.baseUrl} — database: ${db}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    await app.close();
    process.exit(0);
  });
}
