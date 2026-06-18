// api/_lib/observe.js
// Zero-dependency error reporting to Sentry, matching the rest of api/* :
//   • No npm / no SDK — we POST events straight to Sentry's HTTP "store"
//     endpoint with the built-in global `fetch`.
//   • Fully inert without env vars. If SENTRY_DSN isn't set, observeConfigured()
//     is false and reportError() / wrap() become harmless no-ops. Uploading this
//     file will NOT change the live site's behavior until you set SENTRY_DSN.
//   • Never throws and never blocks the response for long (2s hard timeout).
//     A monitoring outage must never turn into an app outage.
//
// Required env var to activate:
//   SENTRY_DSN   — e.g. https://abc123@o456.ingest.sentry.io/789
// Optional:
//   SENTRY_ENVIRONMENT  — defaults to VERCEL_ENV ('production'/'preview') or 'production'
//   SENTRY_RELEASE      — defaults to VERCEL_GIT_COMMIT_SHA if present

const crypto = require('crypto');

let _dsn = null;
let _parsed = null;

function parseDsn() {
  if (_parsed !== null) return _parsed;
  const raw = (process.env.SENTRY_DSN || '').trim();
  if (!raw) return (_parsed = false);
  try {
    const u = new URL(raw);
    const projectId = u.pathname.replace(/^\/+/, '');
    if (!u.username || !projectId) return (_parsed = false);
    _parsed = {
      publicKey: u.username,
      storeUrl: `${u.protocol}//${u.host}/api/${projectId}/store/`
    };
    _dsn = raw;
  } catch (e) {
    _parsed = false;
  }
  return _parsed;
}

function observeConfigured() {
  return Boolean(parseDsn());
}

function environment() {
  return process.env.SENTRY_ENVIRONMENT || process.env.VERCEL_ENV || 'production';
}

// Redact obvious secrets from request headers before they ever leave the box.
function safeHeaders(req) {
  const drop = new Set(['cookie', 'authorization', 'x-api-key', 'apikey']);
  const out = {};
  const h = (req && req.headers) || {};
  for (const k of Object.keys(h)) {
    out[k] = drop.has(k.toLowerCase()) ? '[redacted]' : h[k];
  }
  return out;
}

// Fire an error to Sentry. Best-effort: awaited (so the serverless function
// doesn't die before the POST flushes) but capped at 2s and swallows everything.
// `where` is a short tag for grouping/filtering (e.g. 'magic:request').
async function reportError(err, { req, where, extra } = {}) {
  const dsn = parseDsn();
  if (!dsn) return; // inert until SENTRY_DSN is set
  try {
    const e = err instanceof Error ? err : new Error(String(err));
    const event = {
      event_id: crypto.randomBytes(16).toString('hex'),
      timestamp: new Date().toISOString(),
      platform: 'node',
      level: 'error',
      logger: 'conflicted-api',
      environment: environment(),
      release: process.env.SENTRY_RELEASE || process.env.VERCEL_GIT_COMMIT_SHA || undefined,
      server_name: undefined, // omit hostname (PII-ish, not useful on serverless)
      tags: where ? { where } : undefined,
      exception: { values: [{ type: e.name || 'Error', value: e.message || String(e) }] },
      extra: {
        stack: e.stack || null,
        ...(extra || {})
      },
      request: req
        ? {
            url: req.url,
            method: req.method,
            headers: safeHeaders(req)
          }
        : undefined
    };
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 2000);
    try {
      await fetch(dsn.storeUrl, {
        method: 'POST',
        signal: ctrl.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-Sentry-Auth': `Sentry sentry_version=7, sentry_client=conflicted/1.0, sentry_key=${dsn.publicKey}`
        },
        body: JSON.stringify(event)
      });
    } finally {
      clearTimeout(t);
    }
  } catch (_) {
    // Monitoring must never break the app. Swallow.
  }
}

// Wrap a serverless handler so any UNCAUGHT throw is reported to Sentry and the
// client still gets a clean 500 instead of a hung/garbage response. Handlers that
// already try/catch internally are unaffected; this is the safety net for the
// unexpected. `where` defaults to the request path.
function wrap(handler, where) {
  return async (req, res) => {
    try {
      return await handler(req, res);
    } catch (err) {
      await reportError(err, { req, where: where || (req && req.url) || 'handler' });
      if (!res.headersSent) {
        try {
          res.status(500).json({ error: 'Something went wrong. Please try again.' });
        } catch (_) {
          /* response already torn down */
        }
      }
    }
  };
}

module.exports = { observeConfigured, reportError, wrap };
