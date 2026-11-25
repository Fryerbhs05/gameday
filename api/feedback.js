// api/feedback.js
// In-app "Rate Conflicted" feedback (sw v433).
//
//   GET  /api/feedback                -> { eligible, reason } for the timed ask (signed-in only)
//   POST /api/feedback?action=ask     -> record that the timed ask was shown (events row
//                                        'feedback_ask_shown'; the server counts these, so the
//                                        2-per-season / 30-days-apart cap holds across devices)
//   POST /api/feedback?action=save    -> insert or update this person's feedback row.
//                                        body.final=true also emails the copy to the inbox.
//   GET  /api/feedback?job=sweep      -> Vercel cron (hourly). Emails any row still un-emailed
//                                        an hour after it was made (app closed mid-form).
//
// The timed ask's rules (Matt, 2026-11-25):
//   • signed-in account at least 14 days old that opened the app in 3+ different weeks
//   • at most 2 asks per season (Mar 1 → end of Feb), at least 30 days apart
//   • once they've rated this season, no more asks
// The client adds: never in demo, never in the same visit as the alerts ask, never over
// another sheet, and only on the way BACK to Home from another view.
//
// Email: one copy per feedback row to ConflictedApp@Gmail.com, sent once they're done
// (Send / Skip the rest / closing the sheet after rating) or by the hourly sweep. emailed_at
// is claimed atomically before sending, so a row is never emailed twice. Reply-To is the
// person's account email. Sender: FEEDBACK_FROM env var, default
// "Conflicted Feedback <feedback@conflictedapp.com>" (conflictedapp.com is the domain
// already verified in Resend for the sign-in emails).
//
// Inert without env vars, like the other account endpoints.

const A = require('./_lib/accounts');

const INBOX = process.env.FEEDBACK_TO || 'ConflictedApp@Gmail.com';
const FROM = process.env.FEEDBACK_FROM || 'Conflicted Feedback <feedback@conflictedapp.com>';
const CONSENT = 'Conflicted can quote this on its website and social posts';
const CAPS = ['', 'Not for me', 'Needs work', 'It’s okay', 'Really good', 'Love it'];
const TRIGGERS = { return_home: 'Came back to Home (timed ask)', more_menu: 'More → Rate Conflicted', contact: 'Contact → Rate Conflicted' };
const NAME_STYLES = new Set(['initial', 'first', 'anon']);
const MAX = 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY = 86400000;

async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return await new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

function txt(v, max) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s ? s.slice(0, max || MAX) : null;
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function seasonYear(d) {
  // NFL season key: Mar–Dec = this year, Jan–Feb = last year (matches feedback_eligibility()).
  const ct = new Date((d || new Date()).toLocaleString('en-US', { timeZone: 'America/Chicago' }));
  return ct.getMonth() >= 2 ? ct.getFullYear() : ct.getFullYear() - 1;
}

/* ── Eligibility for the timed ask ─────────────────────────────── */
async function eligibility(uid) {
  const j = (await A.sbFetch('rpc/feedback_eligibility', {
    method: 'POST',
    body: JSON.stringify({ p_uid: uid })
  })) || {};
  if (j.account_days == null) return { eligible: false, reason: 'no_account' };
  if (j.account_days < 14) return { eligible: false, reason: 'new_account' };
  if ((j.open_weeks || 0) < 3) return { eligible: false, reason: 'few_weeks' };
  if (j.rated) return { eligible: false, reason: 'rated' };
  if ((j.asks || 0) >= 2) return { eligible: false, reason: 'max_asks' };
  if (j.last_ask && Date.now() - Date.parse(j.last_ask) < 30 * DAY) return { eligible: false, reason: 'recent_ask' };
  return { eligible: true };
}

/* ── Row shaping: the server decides what's kept, never the client ─ */
function shapeRow(body) {
  const rating = parseInt(body.rating, 10);
  if (!(rating >= 1 && rating <= 5)) return null;
  const sent = body.stage === 'sent';
  const hi = rating >= 4;
  const liked = sent && hi ? txt(body.liked) : null;
  const quoteOk = !!(sent && hi && liked && body.quote_ok === true);
  const now = new Date().toISOString();
  return {
    rating,
    stage: sent ? 'sent' : 'stars_only',
    liked,
    improve: sent && !hi ? txt(body.improve) : null,
    build_next: sent ? txt(body.build_next) : null,
    quote_ok: quoteOk,
    quote_name_style: quoteOk && NAME_STYLES.has(body.quote_name_style) ? body.quote_name_style : (quoteOk ? 'initial' : null),
    quote_ok_at: quoteOk ? now : null,
    quote_consent_text: quoteOk ? CONSENT : null,
    trigger: TRIGGERS[body.trigger] ? body.trigger : null,
    device: txt(body.device, 60),
    app_version: txt(body.app_version, 40),
    updated_at: now
  };
}

/* ── Email ──────────────────────────────────────────────────────── */
async function emailContext(uid) {
  const [users, profiles, leagues] = await Promise.all([
    A.sbFetch(`users?id=eq.${uid}&select=email,created_at`).catch(() => null),
    A.sbFetch(`user_profiles?user_id=eq.${uid}&select=first_name,last_name`).catch(() => null),
    A.sbFetch(`league_connections?user_id=eq.${uid}&season=eq.${seasonYear()}&select=platform`).catch(() => null)
  ]);
  const u = (users && users[0]) || {};
  const p = (profiles && profiles[0]) || {};
  const first = txt(p.first_name, 40), last = txt(p.last_name, 40);
  const local = String(u.email || '').split('@')[0] || 'Someone';
  const name = first ? (last ? `${first} ${last.charAt(0)}.` : first) : local;
  const fullName = [first, last].filter(Boolean).join(' ') || null;
  const counts = {};
  (leagues || []).forEach((l) => { counts[l.platform] = (counts[l.platform] || 0) + 1; });
  const PN = { sleeper: 'Sleeper', espn: 'ESPN', yahoo: 'Yahoo' };
  const plat = Object.keys(counts).map((k) => (PN[k] || k) + (counts[k] > 1 ? ` ×${counts[k]}` : '')).join(', ');
  const total = (leagues || []).length;
  const days = u.created_at ? Math.floor((Date.now() - Date.parse(u.created_at)) / DAY) : null;
  return { email: u.email || null, name, fullName, first: first || local, days, leagues: total, plat };
}

function quoteName(style, ctx) {
  if (style === 'first') return ctx.first;
  if (style === 'anon') return 'A Conflicted user';
  return ctx.name;
}

function buildEmail(row, ctx) {
  const r = row.rating;
  const hi = r >= 4, mid = r === 3;
  const notes = !!(row.liked || row.improve || row.build_next);
  const subject = `${r}★ from ${ctx.name} · ${notes ? 'with notes' : 'stars only'}`;
  const stars = '★★★★★'.slice(0, r) + `<span style="color:#D5DAE1">${'★★★★★'.slice(r)}</span>`;
  const block = (k, v) => `<div style="margin-top:14px"><div style="font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#8a93a3">${k}</div>`
    + `<div style="margin-top:3px;white-space:pre-wrap;${v ? 'color:#1a2233' : 'color:#8a93a3'}">${v ? esc(v) : 'Nothing written'}</div></div>`;
  const quoteLine = !row.liked ? null : row.quote_ok ? `Yes, as “${esc(quoteName(row.quote_name_style, ctx))}”` : 'No';
  const meta = [
    `Came from: ${esc(TRIGGERS[row.trigger] || row.trigger || 'unknown')}`,
    `Account: ${ctx.days != null ? ctx.days + ' days old' : 'age unknown'} · ${ctx.leagues} league${ctx.leagues === 1 ? '' : 's'}${ctx.plat ? ' (' + esc(ctx.plat) + ')' : ''}`,
    `App ${esc(row.app_version || '?')}${row.device ? ' · ' + esc(row.device) : ''}`,
    row.stage === 'sent' ? 'They tapped Send.' : 'Stars only: they closed the sheet without sending notes.',
    ctx.email ? `Hit Reply to answer ${esc(ctx.first)} directly.` : ''
  ].filter(Boolean).join('<br>');
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a2233;font-size:14px;line-height:1.5">`
    + `<div style="font-size:24px;letter-spacing:2px;color:#D9A445">${stars}</div>`
    + `<div style="font-size:13px;color:#5a6472;margin-top:2px">${r} of 5 · ${CAPS[r]}</div>`
    + `<div style="font-weight:600;margin-top:12px">${esc(ctx.fullName || ctx.name)}${ctx.email ? ' · ' + esc(ctx.email) : ''}</div>`
    + (hi ? block('What they like', row.liked) : block(mid ? 'What would make it a 5' : 'What got in the way', row.improve))
    + block('Build next', row.build_next)
    + (quoteLine ? `<div style="margin-top:14px"><div style="font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#8a93a3">OK to quote</div><div style="margin-top:3px">${quoteLine}</div></div>` : '')
    + `<div style="margin-top:18px;border-top:1px solid #E1E5EB;padding-top:10px;font-size:12px;color:#8a93a3;line-height:1.6">${meta}</div>`
    + `</div>`;
  const text = [
    `${r} of 5 · ${CAPS[r]}`,
    `${ctx.fullName || ctx.name}${ctx.email ? ' · ' + ctx.email : ''}`,
    '',
    hi ? `What they like: ${row.liked || '(nothing written)'}` : `${mid ? 'What would make it a 5' : 'What got in the way'}: ${row.improve || '(nothing written)'}`,
    `Build next: ${row.build_next || '(nothing written)'}`,
    quoteLine ? `OK to quote: ${quoteLine.replace(/&[^;]+;/g, '')}` : '',
    '',
    `Came from: ${TRIGGERS[row.trigger] || row.trigger || 'unknown'}`,
    `Account: ${ctx.days != null ? ctx.days + ' days old' : 'age unknown'} · ${ctx.leagues} leagues${ctx.plat ? ' (' + ctx.plat + ')' : ''}`
  ].filter((l) => l !== null).join('\n');
  return { subject, html, text };
}

async function sendEmail(row) {
  if (!A.emailConfigured()) throw new Error('RESEND_API_KEY not set');
  const ctx = await emailContext(row.user_id);
  const { subject, html, text } = buildEmail(row, ctx);
  const payload = { from: FROM, to: [INBOX], subject, html, text };
  if (ctx.email) payload.reply_to = ctx.email;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(`Resend ${r.status}: ${t.slice(0, 300)}`);
  }
}

/* Claim the row (emailed_at null → now) BEFORE sending, so two callers can never both send.
   If the send fails, release the claim so the hourly sweep retries it. */
async function emailOnce(id) {
  const now = new Date().toISOString();
  const claimed = await A.sbFetch(`feedback?id=eq.${id}&emailed_at=is.null`, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ emailed_at: now })
  });
  const row = claimed && claimed[0];
  if (!row) return false;
  try {
    await sendEmail(row);
    return true;
  } catch (e) {
    console.error('feedback email failed:', e.message);
    await A.sbFetch(`feedback?id=eq.${id}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ emailed_at: null })
    }).catch(() => {});
    return false;
  }
}

/* ── Handlers ───────────────────────────────────────────────────── */
async function handleEligibility(req, res, acct) {
  try {
    res.status(200).json(await eligibility(acct.uid));
  } catch (e) {
    console.error('feedback eligibility error:', e.message);
    res.status(200).json({ eligible: false, reason: 'error' });
  }
}

async function handleAsk(req, res, acct) {
  try {
    const body = await readJsonBody(req);
    await A.sbFetch('events', {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ user_id: acct.uid, name: 'feedback_ask_shown', props: { trigger: 'return_home', device: txt(body && body.device, 60) } })
    });
    res.status(204).end();
  } catch (e) {
    console.error('feedback ask error:', e.message);
    res.status(204).end();
  }
}

async function handleSave(req, res, acct) {
  if (!(await A.rateLimitOk(`fb:${acct.uid}`, 40, 3600))) {
    res.status(429).json({ error: 'Too many saves. Try again later.' });
    return;
  }
  const body = (await readJsonBody(req)) || {};
  const row = shapeRow(body);
  if (!row) { res.status(400).json({ error: 'rating must be 1 to 5' }); return; }
  try {
    let saved = null;
    if (body.id && UUID_RE.test(String(body.id))) {
      const upd = await A.sbFetch(`feedback?id=eq.${body.id}&user_id=eq.${acct.uid}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body: JSON.stringify(row)
      });
      saved = upd && upd[0];
    }
    if (!saved) {
      const ins = await A.sbFetch('feedback', {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body: JSON.stringify({ ...row, user_id: acct.uid })
      });
      saved = ins && ins[0];
    }
    if (!saved) throw new Error('no row returned');
    let emailed = !!saved.emailed_at;
    if (body.final === true && !emailed) emailed = await emailOnce(saved.id);
    res.status(200).json({ ok: true, id: saved.id, emailed });
  } catch (e) {
    console.error('feedback save error:', e.message);
    res.status(500).json({ error: 'Could not save your feedback.' });
  }
}

async function handleSweep(req, res) {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.authorization !== `Bearer ${secret}`) { res.status(401).json({ error: 'unauthorized' }); return; }
  if (!A.accountsConfigured()) { res.status(200).json({ ok: true, sent: 0, skipped: 'accounts not configured' }); return; }
  const cutoff = new Date(Date.now() - 3600000).toISOString();
  const rows = (await A.sbFetch(`feedback?emailed_at=is.null&created_at=lt.${encodeURIComponent(cutoff)}&select=id&order=created_at.asc&limit=25`)) || [];
  let sent = 0;
  for (const r of rows) { if (await emailOnce(r.id)) sent++; }
  res.status(200).json({ ok: true, waiting: rows.length, sent });
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  const q = req.query || {};
  if (req.method === 'GET' && q.job === 'sweep') return handleSweep(req, res);
  if (!A.accountsConfigured()) { res.status(503).json({ error: 'Accounts are not enabled.' }); return; }
  const acct = A.readAccount(req);
  if (!acct) { res.status(401).json({ error: 'Not signed in.' }); return; }
  if (req.method === 'GET') return handleEligibility(req, res, acct);
  if (req.method === 'POST') {
    if (q.action === 'ask') return handleAsk(req, res, acct);
    if (q.action === 'save') return handleSave(req, res, acct);
    res.status(400).json({ error: 'Unknown action' });
    return;
  }
  res.setHeader('Allow', 'GET, POST');
  res.status(405).json({ error: 'Method not allowed' });
};

// Error monitoring (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('./_lib/observe').wrap(module.exports, 'feedback');
// Exposed for tests only.
module.exports._test = { shapeRow, buildEmail, seasonYear };
