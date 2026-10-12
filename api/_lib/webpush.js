// api/_lib/webpush.js
// Zero-dependency Web Push sender (same no-npm-deps rule as accounts.js).
//   • Payload encryption: RFC 8291 (aes128gcm) — one record, no padding.
//   • Server identity:    RFC 8292 (VAPID) — ES256 JWT signed with node:crypto.
// Works for every push service a browser hands us: Apple (web.push.apple.com,
// iPhone Home Screen apps on iOS 16.4+), Google FCM (Chrome/Android), Mozilla.
//
// Env vars (Vercel):
//   VAPID_PUBLIC_KEY   — base64url, 65-byte uncompressed P-256 point (also sent to the browser)
//   VAPID_PRIVATE_KEY  — base64url, 32-byte P-256 private scalar (server only)
//   VAPID_SUBJECT      — optional contact for push services, default below

const crypto = require('crypto');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => Buffer.from(String(s || ''), 'base64url');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();

function pushConfigured() {
  return !!(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY);
}
function publicKey() {
  return (process.env.VAPID_PUBLIC_KEY || '').trim();
}

// ES256 JWT for the push service at `audience` (its origin). Valid 12h (Apple caps at 24h).
function vapidJwt(audience) {
  const pub = fromB64u(publicKey());
  const d = (process.env.VAPID_PRIVATE_KEY || '').trim();
  if (pub.length !== 65 || pub[0] !== 4) throw new Error('VAPID_PUBLIC_KEY is not an uncompressed P-256 key');
  const key = crypto.createPrivateKey({
    key: { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)), d },
    format: 'jwk'
  });
  const header = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const payload = b64u(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: (process.env.VAPID_SUBJECT || 'mailto:ConflictedApp@Gmail.com').trim()
  }));
  const data = `${header}.${payload}`;
  const sig = crypto.sign('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' });
  return `${data}.${b64u(sig)}`;
}

// RFC 8291 §3.4 + RFC 8188: encrypt `plaintext` for one subscription.
function encryptPayload(plaintext, p256dh, auth) {
  const uaPublic = fromB64u(p256dh);
  const authSecret = fromB64u(auth);
  if (uaPublic.length !== 65 || authSecret.length < 16) throw new Error('bad subscription keys');

  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey(); // 65-byte uncompressed
  const ecdhSecret = ecdh.computeSecret(uaPublic);
  const salt = crypto.randomBytes(16);

  // IKM = HKDF(auth_secret, ecdh_secret, "WebPush: info\0" || ua_public || as_public, 32)
  const prkKey = hmac(authSecret, ecdhSecret);
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic, Buffer.from([1])]);
  const ikm = hmac(prkKey, keyInfo).subarray(0, 32);

  // CEK / NONCE = HKDF(salt, IKM, "Content-Encoding: aes128gcm\0" / "Content-Encoding: nonce\0")
  const prk = hmac(salt, ikm);
  const cek = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'), Buffer.from([1])])).subarray(0, 16);
  const nonce = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: nonce\0'), Buffer.from([1])])).subarray(0, 12);

  // Single (last) record: plaintext || 0x02, no padding.
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const body = Buffer.concat([
    cipher.update(Buffer.concat([Buffer.from(plaintext), Buffer.from([2])])),
    cipher.final(),
    cipher.getAuthTag()
  ]);

  // Header: salt(16) || record size(uint32 BE) || keyid length(1) || keyid (as_public)
  const rs = Buffer.alloc(4);
  rs.writeUInt32BE(4096, 0);
  return Buffer.concat([salt, rs, Buffer.from([asPublic.length]), asPublic, body]);
}

// Send one notification. `sub` = { endpoint, p256dh, auth }. `message` is JSON-able
// and is what the service worker's push handler receives.
// Returns { ok, status, gone } — gone=true means the subscription is dead (404/410)
// and should be deleted.
async function sendPush(sub, message, { ttl = 3600, urgency = 'high' } = {}) {
  const endpoint = String(sub.endpoint || '');
  const audience = new URL(endpoint).origin;
  const body = encryptPayload(Buffer.from(JSON.stringify(message)), sub.p256dh, sub.auth);
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      TTL: String(ttl),
      Urgency: urgency,
      Authorization: `vapid t=${vapidJwt(audience)}, k=${publicKey()}`
    },
    body
  });
  let text = '';
  if (r.status >= 300) text = await r.text().catch(() => '');
  return { ok: r.status >= 200 && r.status < 300, status: r.status, gone: r.status === 404 || r.status === 410, text: text.slice(0, 300) };
}

module.exports = { pushConfigured, publicKey, vapidJwt, encryptPayload, sendPush };
