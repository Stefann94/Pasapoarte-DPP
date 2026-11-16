import { loadConfig } from './config.js';
import { createApp } from './app.js';

const config = loadConfig();
const app = createApp(config);

app.server.listen(config.port, () => {
  console.log(`DPP hosting listening on port ${config.port} — public base URL ${config.baseUrl}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    app.close();
    process.exit(0);
  });
}
