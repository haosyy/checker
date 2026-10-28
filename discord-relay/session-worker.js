import relay from './worker.js';

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const hash = async value => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))), b => b.toString(16).padStart(2, '0')).join('');
const randomCode = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
const safeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};
const isValidReport = report => report && ['clean', 'review', 'suspicious'].includes(report.status) && Array.isArray(report.found) && report.found.every(item => item && typeof item === 'object');
async function readBody(request) {
  if (!request.body) throw new Error('Missing body');
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 131072) { await reader.cancel(); throw new Error('Body too large'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder().decode(bytes));
}
const forward = (report, env) => relay.fetch(new Request('https://internal/report', {
  method: 'POST',
  headers: { authorization: `Bearer ${env.REPORT_API_TOKEN}`, 'content-type': 'application/json' },
  body: JSON.stringify(report)
}), env);

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (request.method !== 'POST') return json({ error: 'Not found' }, 404);
    if (!env.REPORT_API_TOKEN || !env.CHECK_SESSIONS) return json({ error: 'Server not configured' }, 503);
    const auth = request.headers.get('authorization') || '';
    if (path === '/checks') {
      if (auth !== `Bearer ${env.REPORT_API_TOKEN}`) return json({ error: 'Unauthorized' }, 401);
      const checkCode = randomCode();
      const stub = env.CHECK_SESSIONS.get(env.CHECK_SESSIONS.idFromName(await hash(checkCode)));
      const response = await stub.fetch('https://internal/create', { method: 'POST' });
      if (!response.ok) return json({ error: 'Could not create check' }, 503);
      const session = await response.json();
      return json({ check_code: checkCode, expires_at: session.expiresAt });
    }
    if (path !== '/report') return json({ error: 'Not found' }, 404);
    // Preserve the working administrator-token path during migration.
    if (auth === `Bearer ${env.REPORT_API_TOKEN}`) return relay.fetch(request, env);
    // Long-lived shared player key: one command, unlimited checks, rate limited per IP.
    if (env.PLAYER_KEY && safeEqual(auth, `Bearer ${env.PLAYER_KEY}`)) {
      let report;
      try { report = await readBody(request); } catch { return json({ error: 'Invalid or oversized JSON report' }, 400); }
      if (!isValidReport(report)) return json({ error: 'Invalid report' }, 400);
      const ipKey = await hash(request.headers.get('cf-connecting-ip') || 'unknown');
      const stub = env.CHECK_SESSIONS.get(env.CHECK_SESSIONS.idFromName('shared-' + ipKey));
      const limited = await stub.fetch('https://internal/rate', { method: 'POST' });
      if (!limited.ok) return json({ error: 'Too many checks from this network. Try again later.' }, 429);
      report.check_id = ipKey.slice(0, 12).toUpperCase();
      return forward(report, env);
    }
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!/^[a-f0-9]{64}$/.test(token)) return json({ error: 'Invalid check code' }, 401);
    let report;
    try { report = await readBody(request); } catch { return json({ error: 'Invalid or oversized JSON report' }, 400); }
    if (!isValidReport(report)) return json({ error: 'Invalid report' }, 400);
    const key = await hash(token);
    const stub = env.CHECK_SESSIONS.get(env.CHECK_SESSIONS.idFromName(key));
    const claimed = await stub.fetch('https://internal/consume', { method: 'POST' });
    if (!claimed.ok) return json({ error: 'Check code expired or already used' }, 401);
    report.check_id = key.slice(0, 12).toUpperCase();
    return forward(report, env);
  }
};

export class CheckSession {
  constructor(state) { this.state = state; }
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method !== 'POST') return json({ error: 'Not found' }, 404);
    if (path === '/create') {
      const expiresAt = Date.now() + 60 * 60 * 1000;
      const created = await this.state.storage.transaction(async txn => {
        if (await txn.get('session')) return false;
        await txn.put('session', { expiresAt, used: false });
        return true;
      });
      if (!created) return json({ error: 'Exists' }, 409);
      await this.state.storage.setAlarm(expiresAt + 60000);
      return json({ expiresAt });
    }
    if (path === '/consume') {
      const accepted = await this.state.storage.transaction(async txn => {
        const session = await txn.get('session');
        if (!session || session.used || session.expiresAt <= Date.now()) return false;
        await txn.put('session', { ...session, used: true });
        return true;
      });
      return json({ accepted }, accepted ? 200 : 401);
    }
    if (path === '/rate') {
      const windowMs = 30 * 60 * 1000;
      const limit = 3;
      const allowed = await this.state.storage.transaction(async txn => {
        const now = Date.now();
        const state = (await txn.get('rate')) || { windowStart: now, count: 0 };
        if (now - state.windowStart >= windowMs) { state.windowStart = now; state.count = 0; }
        if (state.count >= limit) return false;
        state.count += 1;
        await txn.put('rate', state);
        return true;
      });
      return json({ allowed }, allowed ? 200 : 429);
    }
    return json({ error: 'Not found' }, 404);
  }
  async alarm() { await this.state.storage.deleteAll(); }
}
