// Vercel entry point. vercel.json rewrites every path to this function; the
// original URL is preserved in req.url, so the app's own router handles it.
// The app instance (DB pool, passport cache) is reused across warm invocations.
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';

let appPromise;

export default async function handler(req, res) {
  // loadConfig runs inside the async function so a config error becomes a
  // rejected promise (handled below) instead of crashing the function.
  appPromise ??= (async () => createApp(loadConfig()))().catch((err) => {
    appPromise = undefined; // retry initialisation on the next request
    throw err;
  });
  let app;
  try {
    app = await appPromise;
  } catch (err) {
    console.error('startup failed:', err);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.end('Server misconfigured: check the environment variables in Vercel (see README).');
  }
  return app.handler(req, res);
}
