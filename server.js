'use strict';

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_CONSOLE_PASSWORD = process.env.ADMIN_CONSOLE_PASSWORD;
const ADMIN_ALLOWED_IP = process.env.ADMIN_ALLOWED_IP || '';
if (!ADMIN_CONSOLE_PASSWORD) {
  console.error('Missing ADMIN_CONSOLE_PASSWORD in .env');
  process.exit(1);
}

const storage = path.join(__dirname, 'storage');
const files = {
  settings: path.join(storage, 'settings.json'),
  users: path.join(storage, 'users.json'),
  pendingRegistrations: path.join(storage, 'pending-registrations.json'),
  invites: path.join(storage, 'invites.json'),
  sessions: path.join(storage, 'sessions.json'),
  betaApplications: path.join(storage, 'beta-applications.json'),
  chatQueue: path.join(storage, 'chat-queue.json'),
  discordChannels: path.join(storage, 'discord-channels.json'),
  chatMessages: path.join(storage, 'chat-messages.json')
};
fs.mkdirSync(storage, { recursive: true });
for (const [name, file] of Object.entries(files)) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, name === 'settings' ? JSON.stringify({ noInviteReg: false }, null, 2) : '[]', 'utf8');
}
function readSettings() {
  const value = JSON.parse(fs.readFileSync(files.settings, 'utf8'));
  return value && typeof value === 'object' && !Array.isArray(value) ? value : { noInviteReg: false };
}
function writeSettings(value) {
  const tmp = files.settings + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, files.settings);
}
function read(name) {
  const data = JSON.parse(fs.readFileSync(files[name], 'utf8'));
  if (!Array.isArray(data)) throw new Error(`${name}.json must contain an array`);
  return data;
}
function write(name, data) {
  const tmp = files[name] + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, files[name]);
}
function randomHex(bytes = 32) { return crypto.randomBytes(bytes).toString('hex'); }
function sha(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function ipOf(req) {
  let ip = req.socket.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}
function adminIpCheck(req, res, next) {
  if (ADMIN_ALLOWED_IP && ipOf(req) !== ADMIN_ALLOWED_IP) {
    return res.status(403).json({ success: false, message: 'Admin access denied from this IP.' });
  }
  next();
}
function cookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); }
    catch { out[k] = part.slice(i + 1).trim(); }
  }
  return out;
}
function currentUser(req) {
  const token = cookies(req).wataszit_session;
  if (!token) return null;
  const session = read('sessions').find(s => s.tokenHash === sha(token) && s.expiresAt > Date.now());
  if (!session) return null;
  return read('users').find(u => u.uid === session.uid) || null;
}
function safeUser(user) {
  if (!user) return null;
  return { uid: user.uid, username: user.username, email: user.email, emailVerified: !!user.emailVerified, location: user.location, hwid: user.hwid, createdAt: user.createdAt };
}
function makeInvite(createdBy) {
  const invites = read('invites');
  let code;
  do { code = 'WATASZIT-' + randomHex(6).toUpperCase(); }
  while (invites.some(i => i.code === code));
  const invite = { code, createdBy, createdAt: Date.now(), usedBy: null, usedAt: null };
  invites.push(invite);
  write('invites', invites);
  return invite;
}
function setSession(res, user) {
  const token = randomHex(48);
  const sessions = read('sessions');
  sessions.push({ tokenHash: sha(token), uid: user.uid, createdAt: Date.now(), expiresAt: Date.now() + 30 * 86400000 });
  write('sessions', sessions);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `wataszit_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=2592000${secure}`);
}
function passwordMatches(provided) {
  const a = Buffer.from(String(provided || ''));
  const b = Buffer.from(ADMIN_CONSOLE_PASSWORD);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function sendVerificationEmail(to, code) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM;
  if (!apiKey || !from) throw new Error('Email verification is not configured. Set RESEND_API_KEY and EMAIL_FROM in .env.');
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from,
      to: [to],
      subject: 'Your Wataszit verification code',
      text: `Your Wataszit registration code is ${code}. It expires in 10 minutes. If you did not request this, ignore this email.`,
      html: `<div style="background:#101010;color:#ddd;padding:28px;font-family:Arial,sans-serif"><h2 style="color:#fff">wata<span style="color:#84ce22">szit</span></h2><p>Use this code to verify your email address:</p><div style="font-size:30px;letter-spacing:8px;font-weight:bold;color:#84ce22;padding:16px 0">${code}</div><p>This code expires in 10 minutes. If you did not request this, ignore this email.</p></div>`
    })
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    console.error('[email provider]', response.status, detail.slice(0, 500));
    throw new Error('Could not send verification email. Check your email provider settings.');
  }
}

app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : process.env.TRUST_PROXY);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public')));
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
app.use('/api', limiter);

app.get('/api/status', (_req, res) => res.json({ success: true, status: 'online' }));
app.get('/api/public-config', (_req, res) => res.json({
  releaseServerUrl: process.env.RELEASE_SERVER_URL || '',
  betaServerUrl: process.env.BETA_SERVER_URL || '',
  noInviteReg: !!readSettings().noInviteReg
}));

app.post('/api/register/start', authLimiter, async (req, res) => {
  try {
    const code = String(req.body?.code || '').trim().toUpperCase();
    const noInviteReg = !!readSettings().noInviteReg;
    const username = String(req.body?.username || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const location = String(req.body?.location || '').trim();
    if ((!noInviteReg && !code) || !username || !email || !password || !location) return res.status(400).json({ success: false, message: 'Please fill in all required fields.' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ success: false, message: 'Username must be 3-20 letters, numbers or underscores.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, message: 'Invalid email address.' });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ success: false, message: 'Password must be 8-128 characters.' });
    if (username.length > 20 || location.length > 80) return res.status(400).json({ success: false, message: 'Some fields are too long.' });
    const users = read('users');
    if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ success: false, message: 'Username is already taken.' });
    if (users.some(u => u.email === email)) return res.status(409).json({ success: false, message: 'Email is already registered.' });
    const invites = read('invites');
    if (!noInviteReg && !invites.some(i => i.code === code && !i.usedBy)) return res.status(400).json({ success: false, message: 'Invalid or already used invite code.' });

    const verificationCode = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const salt = randomHex(16);
    const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
    const pending = read('pendingRegistrations').filter(item => item.expiresAt > Date.now() && item.email !== email);
    const verificationId = crypto.randomUUID();
    pending.push({ verificationId, codeHash: sha(verificationCode), attempts: 0, username, email, location: location.slice(0, 80), password: { salt, hash: passwordHash }, inviteCode: noInviteReg ? null : code, createdAt: Date.now(), expiresAt: Date.now() + 10 * 60 * 1000 });
    write('pendingRegistrations', pending);
    try {
      await sendVerificationEmail(email, verificationCode);
    } catch (mailError) {
      write('pendingRegistrations', pending.filter(item => item.verificationId !== verificationId));
      return res.status(503).json({ success: false, message: mailError.message });
    }
    res.status(202).json({ success: true, verificationId, message: 'Verification code sent. Check your email.' });
  } catch (err) { console.error('[register start]', err); res.status(500).json({ success: false, message: 'Could not start registration.' }); }
});


app.post('/api/register/resend', authLimiter, async (req, res) => {
  try {
    const verificationId = String(req.body?.verificationId || '');
    const pending = read('pendingRegistrations');
    const item = pending.find(entry => entry.verificationId === verificationId && entry.expiresAt > Date.now());
    if (!item) return res.status(400).json({ success: false, message: 'Verification expired. Start registration again.' });
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    item.codeHash = sha(code); item.attempts = 0; item.expiresAt = Date.now() + 10 * 60 * 1000;
    await sendVerificationEmail(item.email, code);
    write('pendingRegistrations', pending);
    res.json({ success: true, message: 'A new verification code has been sent.' });
  } catch (err) { console.error('[register resend]', err); res.status(503).json({ success: false, message: err.message || 'Could not resend verification email.' }); }
});

app.post('/api/register/verify', authLimiter, async (req, res) => {
  try {
    const verificationId = String(req.body?.verificationId || '');
    const code = String(req.body?.code || '').trim();
    if (!verificationId || !/^\d{6}$/.test(code)) return res.status(400).json({ success: false, message: 'Enter the 6-digit email code.' });
    const pending = read('pendingRegistrations');
    const index = pending.findIndex(item => item.verificationId === verificationId);
    if (index < 0) return res.status(400).json({ success: false, message: 'Verification expired. Start registration again.' });
    const item = pending[index];
    if (item.expiresAt <= Date.now()) {
      pending.splice(index, 1); write('pendingRegistrations', pending);
      return res.status(400).json({ success: false, message: 'Verification code expired. Start registration again.' });
    }
    if (item.attempts >= 5) {
      pending.splice(index, 1); write('pendingRegistrations', pending);
      return res.status(429).json({ success: false, message: 'Too many incorrect codes. Start registration again.' });
    }
    if (sha(code) !== item.codeHash) {
      item.attempts += 1; write('pendingRegistrations', pending);
      return res.status(400).json({ success: false, message: 'Incorrect verification code.' });
    }
    const users = read('users');
    if (users.some(u => u.username.toLowerCase() === item.username.toLowerCase() || u.email === item.email)) {
      pending.splice(index, 1); write('pendingRegistrations', pending);
      return res.status(409).json({ success: false, message: 'Username or email is already registered.' });
    }
    const user = { uid: crypto.randomUUID(), username: item.username, email: item.email, location: item.location, hwid: randomHex(16), password: item.password, emailVerified: true, emailVerifiedAt: Date.now(), createdAt: Date.now() };
    const invites = read('invites');
    if (item.inviteCode) {
      const inviteIndex = invites.findIndex(invite => invite.code === item.inviteCode && !invite.usedBy);
      if (inviteIndex < 0) { pending.splice(index, 1); write('pendingRegistrations', pending); return res.status(400).json({ success: false, message: 'Invite is no longer valid. Start registration again.' }); }
      invites[inviteIndex].usedBy = user.uid; invites[inviteIndex].usedAt = Date.now(); write('invites', invites);
    }
    users.push(user); write('users', users);
    pending.splice(index, 1); write('pendingRegistrations', pending);
    setSession(res, user);
    res.status(201).json({ success: true, user: safeUser(user) });
  } catch (err) { console.error('[register verify]', err); res.status(500).json({ success: false, message: 'Could not verify email and create account.' }); }
});


// Password login: compare scrypt hashes without exposing password data.
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const login = String(req.body?.login || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!login || !password) return res.status(400).json({ success: false, message: 'Enter username/email and password.' });
    const user = read('users').find(u => u.username.toLowerCase() === login || u.email === login);
    if (!user || !user.password?.salt || !user.password?.hash) return res.status(401).json({ success: false, message: 'Invalid login or password.' });
    const candidate = await scrypt(password, user.password.salt, 64);
    const expected = Buffer.from(user.password.hash, 'hex');
    if (candidate.length !== expected.length || !crypto.timingSafeEqual(candidate, expected)) return res.status(401).json({ success: false, message: 'Invalid login or password.' });
    setSession(res, user);
    res.json({ success: true, user: safeUser(user) });
  } catch (err) { console.error('[login]', err); res.status(500).json({ success: false, message: 'Login failed.' }); }
});

app.get('/api/me', (req, res) => {
  try { const user = currentUser(req); if (!user) return res.status(401).json({ success: false, authenticated: false }); res.json({ success: true, authenticated: true, user: safeUser(user) }); }
  catch (err) { console.error('[me]', err); res.status(500).json({ success: false, message: 'Could not load account.' }); }
});

app.post('/api/invites/generate', (req, res) => {
  try { const user = currentUser(req); if (!user) return res.status(401).json({ success: false, message: 'You must be logged in.' }); const invite = makeInvite(user.uid); res.status(201).json({ success: true, code: invite.code, invite }); }
  catch (err) { console.error('[invite generate]', err); res.status(500).json({ success: false, message: 'Could not generate invite.' }); }
});

app.post('/api/invites/check', authLimiter, (req, res) => {
  try { const code = String(req.body?.code || '').trim().toUpperCase(); const invite = read('invites').find(i => i.code === code); const valid = !!invite && !invite.usedBy; res.json({ success: true, valid, message: valid ? 'Invite is valid.' : 'Invite is invalid or already used.' }); }
  catch (err) { console.error('[invite check]', err); res.status(500).json({ success: false, valid: false, message: 'Could not check invite.' }); }
});

// Beta applications are stored server-side; the user's IP is never accepted from browser input.
function clientIp(req) {
  let ip = req.ip || req.socket.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}
function betaApps() {
  const file = files.betaApplications;
  if (!fs.existsSync(file)) fs.writeFileSync(file, '[]', 'utf8');
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(data)) throw new Error('beta-applications.json must contain an array');
  return data;
}
function saveBetaApps(data) {
  const file = files.betaApplications;
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

app.post('/api/beta-application', authLimiter, async (req, res) => {
  try {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ success: false, message: 'You must be logged in.' });
    const apps = betaApps();
    const previous = apps.find(a => a.uid === user.uid && (a.status === 'pending' || a.status === 'accepted'));
    if (previous) return res.status(409).json({ success: false, message: 'You already have an active beta application.' });
    const application = {
      id: crypto.randomUUID(), uid: user.uid, username: user.username,
      email: user.email, ip: clientIp(req), status: 'pending',
      createdAt: Date.now(), reviewedAt: null, reviewedBy: null
    };
    apps.push(application);
    saveBetaApps(apps);
    if (process.env.DISCORD_BOT_TOKEN && process.env.DISCORD_BETA_CHANNEL_ID) {
      // The Discord bot polls the pending queue and posts a message with Accept/Decline buttons.
    }
    res.status(201).json({ success: true, application: { id: application.id, status: application.status } });
  } catch (err) { console.error('[beta application]', err); res.status(500).json({ success: false, message: 'Could not submit beta application.' }); }
});

app.get('/api/beta-application/status', (req, res) => {
  try {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ success: false, message: 'You must be logged in.' });
    const application = betaApps().filter(a => a.uid === user.uid).sort((a,b) => b.createdAt-a.createdAt)[0] || null;
    res.json({ success: true, application: application ? { status: application.status, createdAt: application.createdAt } : null });
  } catch (err) { console.error('[beta status]', err); res.status(500).json({ success: false, message: 'Could not load beta application status.' }); }
});

app.get('/api/internal/beta-applications/pending', (req, res) => {
  const secret = process.env.BETA_REVIEW_SECRET || '';
  const supplied = req.headers['x-beta-review-secret'] || '';
  if (!secret || !passwordMatchesSecret(supplied, secret)) {
    return res.status(401).json({ success: false, message: 'Invalid beta review secret.' });
  }
  try {
    const pending = betaApps()
      .filter(application => application.status === 'pending')
      .map(({ id, username, email, ip, createdAt }) => ({ id, username, email, ip, createdAt }));
    res.json({ success: true, applications: pending });
  } catch (err) {
    console.error('[beta pending list]', err);
    res.status(500).json({ success: false, message: 'Could not load pending applications.' });
  }
});

app.post('/api/internal/beta-application/review', (req, res) => {
  const secret = process.env.BETA_REVIEW_SECRET || '';
  const supplied = req.headers['x-beta-review-secret'] || '';
  if (!secret || !passwordMatchesSecret(supplied, secret)) return res.status(401).json({ success: false });
  try {
    const { id, decision, reviewer } = req.body || {};
    if (!id || !['accepted', 'declined'].includes(decision)) return res.status(400).json({ success: false, message: 'Invalid review.' });
    const apps = betaApps();
    const appIndex = apps.findIndex(a => a.id === id);
    if (appIndex < 0) return res.status(404).json({ success: false, message: 'Application not found.' });
    apps[appIndex].status = decision;
    apps[appIndex].reviewedAt = Date.now();
    apps[appIndex].reviewedBy = String(reviewer || 'Discord reviewer').slice(0, 100);
    saveBetaApps(apps);
    res.json({ success: true, application: { id, status: decision } });
  } catch (err) { console.error('[beta review]', err); res.status(500).json({ success: false }); }
});
function passwordMatchesSecret(provided, expected) {
  const a = Buffer.from(String(provided)); const b = Buffer.from(String(expected));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}


// Website-to-Discord chat bridge. Only authenticated users can send messages.
function readArrayFile(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, '[]', 'utf8');
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(value)) throw new Error('Invalid chat storage');
  return value;
}
function saveArrayFile(file, value) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}
function internalSecretOk(req) {
  const expected = process.env.BETA_REVIEW_SECRET || '';
  const supplied = req.headers['x-beta-review-secret'] || '';
  return !!expected && passwordMatchesSecret(supplied, expected);
}
app.get('/api/chat/channels', (req, res) => {
  if (!currentUser(req)) return res.status(401).json({ success: false, message: 'You must be logged in.' });
  res.json({ success: true, channels: readArrayFile(files.discordChannels) });
});
app.get('/api/chat/messages', (req, res) => {
  if (!currentUser(req)) return res.status(401).json({ success: false, message: 'You must be logged in.' });
  const channelId = String(req.query.channelId || '');
  const messages = readArrayFile(files.chatMessages).filter(m => m.channelId === channelId).slice(-80);
  res.json({ success: true, messages });
});
app.post('/api/chat/messages', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ success: false, message: 'You must be logged in.' });
  const channelId = String(req.body?.channelId || '');
  const content = String(req.body?.content || '').trim();
  const channels = readArrayFile(files.discordChannels);
  if (!channels.some(c => c.id === channelId)) return res.status(400).json({ success: false, message: 'Choose a valid server channel.' });
  if (!content || content.length > 1800) return res.status(400).json({ success: false, message: 'Message must contain 1-1800 characters.' });
  const item = { id: crypto.randomUUID(), channelId, username: user.username, content, createdAt: Date.now(), status: 'queued' };
  const queue = readArrayFile(files.chatQueue); queue.push(item); saveArrayFile(files.chatQueue, queue);
  res.status(202).json({ success: true, message: { id: item.id, status: item.status } });
});
// Bot-only endpoints: channel discovery, outbound queue, and delivery confirmation.
app.post('/api/internal/discord/channels', (req, res) => {
  if (!internalSecretOk(req)) return res.status(401).json({ success: false });
  const channels = Array.isArray(req.body?.channels) ? req.body.channels.slice(0, 500) : [];
  saveArrayFile(files.discordChannels, channels.filter(c => c && /^[0-9]{5,30}$/.test(String(c.id)) && typeof c.name === 'string').map(c => ({ id: String(c.id), name: c.name, guildName: String(c.guildName || '').slice(0, 100) })));
  res.json({ success: true, count: channels.length });
});
app.get('/api/internal/discord/queue', (req, res) => {
  if (!internalSecretOk(req)) return res.status(401).json({ success: false });
  res.json({ success: true, messages: readArrayFile(files.chatQueue).filter(m => m.status === 'queued').slice(0, 20) });
});
app.post('/api/internal/discord/delivered', (req, res) => {
  if (!internalSecretOk(req)) return res.status(401).json({ success: false });
  const { id, success: delivered, error } = req.body || {};
  const queue = readArrayFile(files.chatQueue);
  const item = queue.find(m => m.id === id);
  if (!item) return res.status(404).json({ success: false });
  item.status = delivered ? 'sent' : 'failed'; item.error = delivered ? null : String(error || 'Delivery failed').slice(0, 200);
  item.deliveredAt = Date.now(); saveArrayFile(files.chatQueue, queue);
  if (delivered) {
    const messages = readArrayFile(files.chatMessages);
    messages.push({ id: item.id, channelId: item.channelId, username: item.username, content: item.content, createdAt: item.createdAt, sentAt: Date.now() });
    saveArrayFile(files.chatMessages, messages.slice(-2000));
  }
  res.json({ success: true });
});

// The password is checked here on the server. It is never embedded in index.html.
app.post('/api/admin/no-invite-registration', adminIpCheck, authLimiter, (req, res) => {
  try {
    if (!passwordMatches(req.body?.password)) return res.status(401).json({ success: false, message: 'Incorrect admin password.' });
    const settings = readSettings();
    settings.noInviteReg = !settings.noInviteReg;
    writeSettings(settings);
    res.json({ success: true, noInviteReg: settings.noInviteReg });
  } catch (err) { console.error('[admin no-invite registration]', err); res.status(500).json({ success: false, message: 'Could not update registration setting.' }); }
});

app.post('/api/admin/console-invite', adminIpCheck, authLimiter, (req, res) => {
  try {
    if (!passwordMatches(req.body?.password)) return res.status(401).json({ success: false, message: 'Incorrect admin password.' });
    const invite = makeInvite('admin-console');
    res.status(201).json({ success: true, code: invite.code, invite });
  } catch (err) { console.error('[admin console invite]', err); res.status(500).json({ success: false, message: 'Could not generate invite.' }); }
});

app.post('/api/logout', (req, res) => {
  try {
    const token = cookies(req).wataszit_session;
    if (token) write('sessions', read('sessions').filter(s => s.tokenHash !== sha(token)));
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `wataszit_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`);
    res.json({ success: true });
  } catch (err) { console.error('[logout]', err); res.status(500).json({ success: false, message: 'Logout failed.' }); }
});

app.use('/api', (_req, res) => res.status(404).json({ success: false, message: 'API endpoint not found.' }));
app.listen(PORT, '0.0.0.0', () => console.log(`Wataszit running on port ${PORT}`));
