'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const {
  JWT_SECRET, ENC_KEY, NODE_ENV, PORT = 3000, RESEND_API_KEY,
  RESEND_FROM_EMAIL = 'onboarding@resend.dev', DATABASE_URL
} = process.env;
const PROD = NODE_ENV === 'production' || Boolean(process.env.VERCEL);
if (!JWT_SECRET || JWT_SECRET.length < 48 || !/^[0-9a-f]{64}$/i.test(ENC_KEY || '')) {
  throw new Error('Missing secrets. Run `npm run keygen` and configure JWT_SECRET and ENC_KEY.');
}
if (!DATABASE_URL) throw new Error('DATABASE_URL is required. Configure your Neon PostgreSQL connection string.');

const KEY = Buffer.from(ENC_KEY, 'hex');
const ISS = 'harbor-sl';
const AUD = 'harbor-web';
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: true },
  max: PROD ? 5 : 10,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name_enc TEXT NOT NULL,
  pw TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','officer')),
  balance BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0),
  failed INTEGER NOT NULL DEFAULT 0,
  locked_until BIGINT NOT NULL DEFAULT 0,
  last_login BIGINT,
  prev_login BIGINT
);
CREATE TABLE IF NOT EXISTS otps (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  expires BIGINT NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS revoked (
  jti TEXT PRIMARY KEY,
  exp BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS txns (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  kind TEXT,
  amount BIGINT,
  ts BIGINT
);
CREATE TABLE IF NOT EXISTS loans (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  amount BIGINT,
  term INTEGER,
  payment BIGINT,
  purpose_enc TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  ts BIGINT
);
CREATE TABLE IF NOT EXISTS audit (
  id BIGSERIAL PRIMARY KEY,
  ts BIGINT,
  user_id BIGINT,
  event TEXT,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_txns_user_id_id ON txns(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_loans_user_id_id ON loans(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_loans_status ON loans(status);
CREATE INDEX IF NOT EXISTS idx_revoked_exp ON revoked(exp);
`;
let schemaPromise;
async function ensureSchema() {
  if (!schemaPromise) schemaPromise = pool.query(SCHEMA).catch(err => { schemaPromise = null; throw err; });
  await schemaPromise;
}

const now = () => Date.now();
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const log = async (userId, event, ip) => {
  await pool.query('INSERT INTO audit(ts,user_id,event,ip) VALUES($1,$2,$3,$4)', [now(), userId, event, ip || null]);
};
const enc = text => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
};
const dec = value => {
  const raw = Buffer.from(value, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
};
const hashPw = async password => {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(password, salt, 64)).toString('hex');
};
const checkPw = async (password, stored) => {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const derived = await scrypt(password, Buffer.from(saltHex, 'hex'), 64);
    const expected = Buffer.from(hashHex, 'hex');
    return expected.length === derived.length && crypto.timingSafeEqual(derived, expected);
  } catch { return false; }
};
let DUMMY;
const dummyHashReady = hashPw('placeholder').then(value => { DUMMY = value; });
const weakPw = (password, email) => password.length < 12 || password.length > 128 ||
  !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) ||
  !/[^A-Za-z0-9]/.test(password) || /password|qwerty|123456|letmein|welcome|admin|harbor|savings/i.test(password) ||
  (email.split('@')[0].length > 3 && password.toLowerCase().includes(email.split('@')[0]));

const cookieOptions = { httpOnly: true, secure: PROD, sameSite: 'Strict', path: '/' };
function setCookie(res, name, value, maxAgeSeconds) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (PROD) parts.push('Secure');
  if (Number.isFinite(maxAgeSeconds)) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`);
  res.append('Set-Cookie', parts.join('; '));
}
function clearCookie(res, name) { setCookie(res, name, '', 0); }
const sign = (payload, expiresIn) => jwt.sign(payload, JWT_SECRET, {
  algorithm: 'HS256', expiresIn, issuer: ISS, audience: AUD, jwtid: crypto.randomUUID()
});
const verify = token => jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer: ISS, audience: AUD });
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(part => {
    const i = part.indexOf('=');
    return i < 0 ? [] : [part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1).trim())];
  }).filter(pair => pair.length === 2));
}

const app = express();
app.set('trust proxy', PROD ? 1 : false);
app.disable('x-powered-by');
if (PROD) app.use((req, res, next) => req.secure ? next() : res.redirect(301, 'https://' + req.headers.host + req.originalUrl));
app.use(helmet({
  contentSecurityPolicy: { useDefaults: false, directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
    imgSrc: ["'self'", 'data:'], objectSrc: ["'none'"], frameAncestors: ["'none'"],
    baseUri: ["'self'"], formAction: ["'self'"], ...(PROD ? { upgradeInsecureRequests: [] } : {})
  } },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));
const limiter = (limit, extra = {}) => rateLimit({ windowMs: 15 * 60 * 1000, limit, standardHeaders: true, legacyHeaders: false, ...extra });
app.use(limiter(300));
const authLimit = limiter(15, { message: { error: 'Too many attempts. Try again later.' } });
app.use('/api', async (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  try { await ensureSchema(); next(); } catch (err) { console.error('Database initialization failed:', err.message); res.status(503).json({ error: 'The service is temporarily unavailable.' }); }
});
app.use('/api', (req, res, next) => req.method === 'GET' || req.is('json') ? next() : res.status(415).json({ error: 'Unsupported request.' }));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore', maxAge: PROD ? '1h' : 0 }));

const bad = (res, message = 'Invalid request.', status = 400) => res.status(status).json({ error: message });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const str = (value, max) => typeof value === 'string' ? value.trim().slice(0, max) : '';
const cents = value => /^\d{1,7}(\.\d{1,2})?$/.test(String(value)) ? Math.round(parseFloat(value) * 100) : 0;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const auth = (...roles) => asyncRoute(async (req, res, next) => {
  try {
    const claims = verify(cookies(req).sid || '');
    if (claims.scope !== 'access') throw new Error('Invalid scope');
    const revoked = await pool.query('SELECT 1 FROM revoked WHERE jti=$1', [claims.jti]);
    if (revoked.rowCount) throw new Error('Revoked token');
    if (req.method !== 'GET' && req.get('x-csrf-token') !== claims.csrf) return bad(res, 'Request blocked.', 403);
    const result = await pool.query('SELECT * FROM users WHERE id=$1', [claims.sub]);
    const user = result.rows[0];
    if (!user || (roles.length && !roles.includes(user.role))) return bad(res, 'Not permitted.', 403);
    req.user = user; req.claims = claims; next();
  } catch { return bad(res, 'Please sign in.', 401); }
});

async function sendMfaEmail(to, code) {
  if (!RESEND_API_KEY) throw new Error('Email delivery is not configured.');
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: `Harbor Savings & Loan <${RESEND_FROM_EMAIL}>`, to: [to],
      subject: 'Your Harbor sign-in verification code',
      text: `Your Harbor verification code is ${code}. It expires in 5 minutes. If you did not try to sign in, ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;color:#172033"><h2>Harbor Savings &amp; Loan</h2><p>Use this code to finish signing in:</p><p style="font-size:30px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in 5 minutes and can only be used once.</p><p>If you did not try to sign in, ignore this message.</p></div>`
    })
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    console.error('Resend delivery failed:', response.status, detail.slice(0, 300));
    throw new Error('We could not send your verification email. Please try again later.');
  }
}

app.post('/api/register', authLimit, asyncRoute(async (req, res) => {
  const body = req.body || {};
  const name = str(body.name, 80), email = str(body.email, 100).toLowerCase();
  const password = typeof body.password === 'string' ? body.password : '';
  if (name.length < 2 || !EMAIL.test(email) || weakPw(password, email))
    return bad(res, 'Check your details. Passwords need 12+ characters with upper, lower, number and symbol.');
  const exists = await pool.query('SELECT 1 FROM users WHERE email=$1', [email]);
  if (!exists.rowCount) {
    await pool.query('INSERT INTO users(email,name_enc,pw) VALUES($1,$2,$3)', [email, enc(name), await hashPw(password)]);
    await log(null, 'register', req.ip);
  }
  res.status(201).json({ ok: true });
}));

app.post('/api/login', authLimit, asyncRoute(async (req, res) => {
  const body = req.body || {};
  const email = str(body.email, 100).toLowerCase();
  const password = typeof body.password === 'string' ? body.password.slice(0, 128) : '';
  const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (!DUMMY) await dummyHashReady;
  const good = await checkPw(password, user ? user.pw : DUMMY);
  const fail = () => bad(res, 'Sign-in failed. Check your details or try again later.', 401);
  if (!user || Number(user.locked_until) > now()) return fail();
  if (!good) {
    const failures = Number(user.failed) + 1;
    await pool.query('UPDATE users SET failed=$1,locked_until=$2 WHERE id=$3', [failures % 5, failures >= 5 ? now() + 9e5 : 0, user.id]);
    await log(user.id, failures >= 5 ? 'locked' : 'login_fail', req.ip);
    return fail();
  }
  await pool.query('UPDATE users SET failed=0 WHERE id=$1', [user.id]);
  const code = String(crypto.randomInt(1e6)).padStart(6, '0');
  await pool.query(`INSERT INTO otps(user_id,code,expires,tries) VALUES($1,$2,$3,0)
    ON CONFLICT(user_id) DO UPDATE SET code=EXCLUDED.code,expires=EXCLUDED.expires,tries=0`, [user.id, sha(code), now() + 3e5]);
  try { await sendMfaEmail(user.email, code); }
  catch (err) {
    await pool.query('DELETE FROM otps WHERE user_id=$1', [user.id]);
    await log(user.id, 'mfa_email_failed', req.ip);
    return bad(res, err.message || 'Verification email could not be sent.', 503);
  }
  setCookie(res, 'mfa', sign({ sub: user.id, scope: 'mfa' }, '5m'), 300);
  await log(user.id, 'mfa_email_sent', req.ip);
  res.json({ mfa: true, message: 'A verification code has been sent to your registered email address.' });
}));

app.post('/api/mfa', authLimit, asyncRoute(async (req, res) => {
  let claims;
  try { claims = verify(cookies(req).mfa || ''); if (claims.scope !== 'mfa') throw new Error('Invalid scope'); }
  catch { return bad(res, 'Code expired. Sign in again.', 401); }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query('SELECT * FROM otps WHERE user_id=$1 FOR UPDATE', [claims.sub]);
    const otp = result.rows[0];
    const code = str(req.body && req.body.code, 6);
    if (!otp || Number(otp.expires) < now() || Number(otp.tries) >= 5) {
      await client.query('ROLLBACK'); return bad(res, 'Code expired. Sign in again.', 401);
    }
    await client.query('UPDATE otps SET tries=tries+1 WHERE user_id=$1', [claims.sub]);
    const valid = /^\d{6}$/.test(code) && crypto.timingSafeEqual(Buffer.from(sha(code)), Buffer.from(otp.code));
    if (!valid) { await client.query('COMMIT'); return bad(res, 'Incorrect code.', 401); }
    await client.query('DELETE FROM otps WHERE user_id=$1', [claims.sub]);
    await client.query('UPDATE users SET prev_login=last_login,last_login=$1 WHERE id=$2', [now(), claims.sub]);
    await client.query('COMMIT');
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
  const csrf = crypto.randomBytes(24).toString('hex');
  setCookie(res, 'sid', sign({ sub: claims.sub, scope: 'access', csrf }, '15m'), 900);
  clearCookie(res, 'mfa');
  await log(claims.sub, 'login', req.ip);
  res.json({ ok: true });
}));

app.get('/api/health', asyncRoute(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, database: 'connected' });
}));

app.get('/api/me', auth(), asyncRoute(async (req, res) => {
  res.json({ name: dec(req.user.name_enc), email: req.user.email, role: req.user.role,
    balance: Number(req.user.balance), lastLogin: req.user.prev_login == null ? null : Number(req.user.prev_login), csrf: req.claims.csrf });
}));
app.post('/api/logout', auth(), asyncRoute(async (req, res) => {
  await pool.query('INSERT INTO revoked(jti,exp) VALUES($1,$2) ON CONFLICT(jti) DO NOTHING', [req.claims.jti, req.claims.exp]);
  clearCookie(res, 'sid');
  await log(req.user.id, 'logout', req.ip);
  res.json({ ok: true });
}));

async function moveMoney(req, res, kind) {
  const amount = cents(req.body && req.body.amount);
  if (!amount) return bad(res, 'Enter a valid amount.');
  const delta = kind === 'deposit' ? amount : -amount;
  const client = await pool.connect();
  let balance;
  try {
    await client.query('BEGIN');
    const updated = await client.query('UPDATE users SET balance=balance+$1 WHERE id=$2 AND balance+$1>=0 RETURNING balance', [delta, req.user.id]);
    if (!updated.rowCount) { await client.query('ROLLBACK'); return bad(res, 'Insufficient funds.'); }
    await client.query('INSERT INTO txns(user_id,kind,amount,ts) VALUES($1,$2,$3,$4)', [req.user.id, kind, amount, now()]);
    balance = Number(updated.rows[0].balance);
    await client.query('COMMIT');
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
  await log(req.user.id, kind, req.ip);
  res.json({ balance });
}
app.post('/api/deposit', auth(), asyncRoute((req, res) => moveMoney(req, res, 'deposit')));
app.post('/api/withdraw', auth(), asyncRoute((req, res) => moveMoney(req, res, 'withdraw')));
app.get('/api/transactions', auth(), asyncRoute(async (req, res) => {
  const result = await pool.query('SELECT kind,amount,ts FROM txns WHERE user_id=$1 ORDER BY id DESC LIMIT 8', [req.user.id]);
  res.json(result.rows.map(row => ({ ...row, amount: Number(row.amount), ts: Number(row.ts) })));
}));

app.post('/api/loans', auth(), asyncRoute(async (req, res) => {
  const body = req.body || {}, amount = Number(body.amount), term = Number(body.term), purpose = str(body.purpose, 200);
  if (!Number.isInteger(amount) || amount < 500 || amount > 50000 || !Number.isInteger(term) || term < 6 || term > 60 || purpose.length < 3)
    return bad(res, 'Amount $500 to $50,000, term 6 to 60 months, and a purpose are required.');
  const pending = await pool.query("SELECT COUNT(*)::int AS count FROM loans WHERE user_id=$1 AND status='pending'", [req.user.id]);
  if (pending.rows[0].count >= 3) return bad(res, 'You already have 3 pending applications.');
  const monthlyRate = .085 / 12;
  const payment = Math.round(amount * 100 * monthlyRate / (1 - Math.pow(1 + monthlyRate, -term)));
  await pool.query('INSERT INTO loans(user_id,amount,term,payment,purpose_enc,ts) VALUES($1,$2,$3,$4,$5,$6)',
    [req.user.id, amount * 100, term, payment, enc(purpose), now()]);
  await log(req.user.id, 'loan_apply', req.ip);
  res.status(201).json({ ok: true });
}));
app.get('/api/loans', auth(), asyncRoute(async (req, res) => {
  const result = await pool.query('SELECT id,amount,term,payment,purpose_enc,status,ts FROM loans WHERE user_id=$1 ORDER BY id DESC', [req.user.id]);
  res.json(result.rows.map(({ purpose_enc, ...loan }) => ({ ...loan, id: Number(loan.id), amount: Number(loan.amount), payment: Number(loan.payment), ts: Number(loan.ts), purpose: dec(purpose_enc) })));
}));
app.get('/api/officer/loans', auth('officer'), asyncRoute(async (req, res) => {
  const result = await pool.query("SELECT l.id,l.amount,l.term,l.purpose_enc,u.email FROM loans l JOIN users u ON u.id=l.user_id WHERE l.status='pending' ORDER BY l.id");
  res.json(result.rows.map(({ purpose_enc, ...loan }) => ({ ...loan, id: Number(loan.id), amount: Number(loan.amount), purpose: dec(purpose_enc) })));
}));
app.patch('/api/officer/loans/:id', auth('officer'), asyncRoute(async (req, res) => {
  const status = req.body && req.body.status, id = Number(req.params.id);
  if (!['approved', 'rejected'].includes(status) || !Number.isSafeInteger(id)) return bad(res);
  const client = await pool.connect();
  let updated = false;
  try {
    await client.query('BEGIN');
    const found = await client.query("SELECT * FROM loans WHERE id=$1 AND status='pending' FOR UPDATE", [id]);
    const loan = found.rows[0];
    if (!loan || String(loan.user_id) === String(req.user.id)) { await client.query('ROLLBACK'); return bad(res, 'Not found.', 404); }
    await client.query('UPDATE loans SET status=$1 WHERE id=$2', [status, id]);
    if (status === 'approved') {
      await client.query('UPDATE users SET balance=balance+$1 WHERE id=$2', [loan.amount, loan.user_id]);
      await client.query("INSERT INTO txns(user_id,kind,amount,ts) VALUES($1,'loan',$2,$3)", [loan.user_id, loan.amount, now()]);
    }
    await client.query('COMMIT'); updated = true;
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
  if (!updated) return bad(res, 'Not found.', 404);
  await log(req.user.id, `loan_${status}_${id}`, req.ip);
  res.json({ ok: true });
}));

app.use('/api', (req, res) => bad(res, 'Not found.', 404));
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.type) return bad(res, 'Invalid request.', err.status || 400);
  console.error('Unhandled application error:', err.message);
  res.status(500).json({ error: 'Something went wrong.' });
});

if (!process.env.VERCEL) {
  const server = app.listen(PORT, () => console.log(`Harbor Savings & Loan on :${PORT}`));
  server.headersTimeout = 15000;
  server.requestTimeout = 15000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 50;
}
module.exports = app;
