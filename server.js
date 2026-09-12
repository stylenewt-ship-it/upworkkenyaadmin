'use strict';

/**
 * Upwork Kenya - backend server
 * Express + pure-JS JSON datastore. No native modules -> builds cleanly on Render.
 */

try { require('dotenv').config(); } catch { /* dotenv optional — env vars may come from the host */ }
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');
const { dailyTasksFor } = require('./tasks.seed');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '11upwork72';
const SESSION_SECRET = process.env.SESSION_SECRET || 'upwork-ke-dev-secret-change-me';

/* 10mb: profile photos uploaded from the device travel as base64 data URLs. */
app.use(express.json({ limit: '10mb' }));

/* CORS: allow the frontend (any origin) to call this API. No behaviour change for same-origin. */
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-auth-token, x-admin-key');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

/* ---------------------------------- auth ---------------------------------- */

function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
}
function token() { return crypto.randomBytes(32).toString('hex'); }
function sign(s) { return crypto.createHmac('sha256', SESSION_SECRET).update(s).digest('hex').slice(0, 16); }

function publicUser(u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}

function getSessionUser(req) {
  const t = req.headers['x-auth-token'] || (req.query && req.query.token);
  if (!t) return null;
  const data = db.load();
  const sess = data.sessions[t];
  if (!sess) return null;
  const u = data.users.find(x => x.id === sess.userId);
  return u || null;
}

function requireAuth(req, res, next) {
  const u = getSessionUser(req);
  if (!u) return res.status(401).json({ error: 'Please log in first.' });
  if (u.suspended) return res.status(403).json({ error: 'Account suspended. Contact support.' });
  req.user = u;
  next();
}

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || (req.query && req.query.key);
  if (key !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid admin credentials.' });
  next();
}

function addTx(userId, type, amount, note) {
  const data = db.load();
  const u = data.users.find(x => x.id === userId);
  if (!u) return null;
  u.wallet = Math.round((u.wallet + amount) * 100) / 100;
  const tx = { id: db.uid('tx'), userId, type, amount, note, at: Date.now(), balanceAfter: u.wallet };
  data.transactions.unshift(tx);
  db.save();
  return tx;
}

function notify(userId, text, kind) {
  const data = db.load();
  data.notifications.unshift({ id: db.uid('ntf'), userId, text, kind: kind || 'info', read: false, at: Date.now() });
  db.save();
}

/* ------------------------------ auth routes ------------------------------- */

app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const data = db.load();
  const em = String(email).trim().toLowerCase();
  if (data.users.some(u => u.email === em)) return res.status(409).json({ error: 'That email is already registered. Try logging in.' });
  const u = {
    id: db.uid('usr'),
    name: String(name).trim(),
    email: em,
    passwordHash: hashPassword(password),
    wallet: 0,
    tier: null,                     // no active package until the user pays to unlock one
    unlockedPackages: [],           // list of package keys the user has paid to unlock
    verified: false,
    investments: [],
    avatar: '',
    bio: '', skills: [], experience: '',
    testPassed: false, bestWpm: 0,
    starterGigClaimed: false,       // free gig awarded once, right after passing the typing test
    suspended: false,
    createdAt: Date.now(),
    lastDailyReset: ''
  };
  data.users.push(u);
  const t = token();
  data.sessions[t] = { userId: u.id, createdAt: Date.now() };
  notify(u.id, 'Karibu! Welcome to Upwork Kenya. Pass the typing test to earn your free starter gig, then unlock a package to begin daily tasks.', 'success');
  db.save();
  res.json({ token: t, user: publicUser(u) });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const data = db.load();
  const u = data.users.find(x => x.email === String(email || '').trim().toLowerCase());
  if (!u || !verifyPassword(password || '', u.passwordHash)) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  const t = token();
  data.sessions[t] = { userId: u.id, createdAt: Date.now() };
  db.save();
  res.json({ token: t, user: publicUser(u) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const data = db.load();
  const t = req.headers['x-auth-token'];
  delete data.sessions[t];
  db.save();
  res.json({ ok: true });
});

app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body || {};
  const data = db.load();
  const u = data.users.find(x => x.email === String(email || '').trim().toLowerCase());
  // Always respond OK to avoid leaking which emails exist
  if (u) {
    const t = token() + sign(u.id);
    data.resetTokens[t] = { email: u.email, expiresAt: Date.now() + 15 * 60 * 1000 };
    // No SMTP on free hosting: surface the reset link (demo). In production, email it.
    console.log(`[reset] link for ${u.email}: /reset.html?token=${t}`);
    db.save();
    return res.json({ ok: true, message: 'If that email exists, a reset link has been created.', devResetToken: t });
  }
  res.json({ ok: true, message: 'If that email exists, a reset link has been created.' });
});

app.post('/api/reset-password', (req, res) => {
  const { token: tk, password } = req.body || {};
  const data = db.load();
  const rec = data.resetTokens[tk];
  if (!rec || rec.expiresAt < Date.now()) return res.status(400).json({ error: 'Reset link is invalid or expired.' });
  if (String(password || '').length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const u = data.users.find(x => x.email === rec.email);
  if (!u) return res.status(400).json({ error: 'Account not found.' });
  u.passwordHash = hashPassword(password);
  delete data.resetTokens[tk];
  db.save();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

/* -------------------------------- profile --------------------------------- */

app.put('/api/profile', requireAuth, (req, res) => {
  const { name, bio, skills, experience, avatar } = req.body || {};
  const u = req.user;
  if (name) u.name = String(name).trim().slice(0, 60);
  if (bio !== undefined) u.bio = String(bio).slice(0, 500);
  if (Array.isArray(skills)) u.skills = skills.map(s => String(s).slice(0, 40)).slice(0, 12);
  if (experience !== undefined) u.experience = String(experience).slice(0, 500);
  if (avatar !== undefined) {
    const a = String(avatar);
    // Device uploads arrive as base64 data: URLs; plain https links still accepted.
    if (a === '' || /^data:image\/(png|jpe?g|webp|gif);base64,/i.test(a) || /^https?:\/\//i.test(a)) {
      u.avatar = a.slice(0, 700000); // ~500KB of base64 — plenty for a 320px profile photo
    }
  }
  db.save();
  res.json({ user: publicUser(u) });
});

app.post('/api/typing-test', requireAuth, (req, res) => {
  const { wpm, accuracy } = req.body || {};
  const w = Number(wpm) || 0, a = Number(accuracy) || 0;
  const u = req.user;
  if (w > u.bestWpm) u.bestWpm = Math.round(w);
  // Professional threshold: 30+ WPM at 90%+ accuracy.
  const passed = w >= 30 && a >= 90;
  let starterGig = null;
  if (passed && !u.testPassed) {
    u.testPassed = true;
    // Award a one-off FREE starter gig — the money reflects in the earnings wallet.
    if (!u.starterGigClaimed) {
      const reward = 150;
      u.starterGigClaimed = true;
      addTx(u.id, 'starter_gig', reward, 'Welcome starter gig — awarded for passing the typing test');
      notify(u.id, `Excellent! You passed the typing test (${Math.round(w)} WPM, ${Math.round(a)}% accuracy). KES ${reward} starter gig credited to your wallet. Unlock a package to start earning daily.`, 'success');
      starterGig = { amount: reward, note: 'Welcome starter gig' };
    } else {
      notify(u.id, `You passed the typing test again (${Math.round(w)} WPM, ${Math.round(a)}% accuracy).`, 'success');
    }
  }
  db.saveNow();
  res.json({ passed, bestWpm: u.bestWpm, testPassed: u.testPassed, starterGig, wallet: u.wallet });
});

app.post('/api/verify', requireAuth, (req, res) => {
  // Paid verification badge (KES 450). Manual M-Pesa code fallback path.
  const u = req.user;
  if (u.verified) return res.json({ ok: true, user: publicUser(u), message: 'Already verified.' });
  const { mpesaRef } = req.body || {};
  if (!mpesaRef || String(mpesaRef).trim().length < 6) {
    return res.status(400).json({ error: `Enter your M-Pesa confirmation code for the KES ${VERIFICATION_PRICE} verification payment.` });
  }
  u.verified = true;
  u.verificationRef = String(mpesaRef).trim();
  notify(u.id, 'You are now a Verified freelancer! The blue badge is on your profile and you receive priority gigs.', 'success');
  db.saveNow();
  res.json({ ok: true, user: publicUser(u) });
});

/* ----------------------------- tasks & earning ----------------------------- */

/* Earning packages. Each package is a one-off PAID unlock via M-Pesa STK push.
   Once unlocked, its daily tasks appear in the user's daily drop and pay at the
   package rate. Verified members get +1 task/day and a 15% pay boost on every gig. */
const PACKAGES = {
  basic:       { name: 'Basic',        order: 1, tasksPerDay: 2, payPerTask: 60,  price: 500,  color: '#22c55e', tagline: 'Entry-level package — a great place to start' },
  premium:     { name: 'Premium',      order: 2, tasksPerDay: 3, payPerTask: 80,  price: 1000, color: '#0ea5a0', tagline: 'A step up for consistent earners' },
  advanced:    { name: 'Advanced',     order: 3, tasksPerDay: 4, payPerTask: 120, price: 2000, color: '#3b82f6', tagline: 'Higher-paying gigs every day' },
  pro:         { name: 'Pro',          order: 4, tasksPerDay: 5, payPerTask: 180, price: 3000, color: '#8b5cf6', tagline: 'Five gigs a day, serious income' },
  advancedPro: { name: 'Advanced Pro', order: 5, tasksPerDay: 6, payPerTask: 260, price: 5000, color: '#f59e0b', tagline: 'Top tier — maximum daily earnings' }
};

const VERIFICATION_PRICE = 450;

/* Investor Funds: fixed, sustainable returns paid ONCE at plan maturity.
   Funds are locked for the plan period, then withdrawn back to the earnings wallet. */
const INVEST_PLANS = [
  { id: 'weekly',  name: '7-Day Plan',   days: 7,   rate: 0.02, desc: 'Short lock-in, modest fixed return' },
  { id: 'monthly', name: '30-Day Plan',  days: 30,  rate: 0.05, desc: 'One month lock-in, higher fixed return' },
  { id: 'annual',  name: '365-Day Plan', days: 365, rate: 0.20, desc: 'Long-term lock-in, best fixed return' }
];

function payForTierFactory(u) {
  const p = PACKAGES[u.tier] || PACKAGES.basic;
  const boost = u.verified ? 1.15 : 1;
  return () => Math.round(p.payPerTask * boost);
}

function hasUnlockedPackage(u, key) {
  return Array.isArray(u.unlockedPackages) && u.unlockedPackages.indexOf(key) !== -1;
}

function highestUnlockedTier(u) {
  const owned = (u.unlockedPackages || []);
  let best = null;
  for (const key of owned) {
    const p = PACKAGES[key];
    if (!p) continue;
    if (!best || p.order > PACKAGES[best].order) best = key;
  }
  return best;
}

function lifetimeEarned(data, userId) {
  const fromTasks = data.assignments.filter(a => a.userId === userId).reduce((s, a) => s + (a.gross || a.net || 0), 0);
  const fromOrders = data.orders.filter(o => o.sellerId === userId && o.status === 'completed').reduce((s, o) => s + o.price, 0);
  return fromTasks + fromOrders;
}

function checkTierUpgrade(u /*, data */) {
  // Sync the user's active tier with the highest package they have paid to unlock.
  const best = highestUnlockedTier(u);
  if (best && best !== u.tier) {
    u.tier = best;
    const p = PACKAGES[best];
    notify(u.id, `Active package set to ${p.name}. You now receive ${p.tasksPerDay} tasks/day at KES ${p.payPerTask} each — up to KES ${p.tasksPerDay * p.payPerTask} per day.`, 'success');
    return true;
  }
  return false;
}

app.get('/api/tasks/today', requireAuth, (req, res) => {
  const u = req.user;
  if (!u.testPassed) return res.status(403).json({ error: 'Pass the typing test first to unlock daily tasks.', needsTest: true });
  if (!u.tier || !PACKAGES[u.tier]) {
    return res.status(403).json({ error: 'Unlock a package first to receive your daily tasks.', needsPackage: true });
  }
  const data = db.load();
  const t = PACKAGES[u.tier];
  const count = t.tasksPerDay + (u.verified ? 1 : 0);
  const tasks = dailyTasksFor(u.id, count, payForTierFactory(u));
  const today = new Date().toISOString().slice(0, 10);
  const doneToday = data.assignments.filter(a => a.userId === u.id && a.day === today).map(a => a.taskKey);
  res.json({ tier: u.tier, tierInfo: t, tasks: tasks.map(x => ({ ...x, done: doneToday.includes(x.key) })) });
});

app.post('/api/tasks/submit', requireAuth, (req, res) => {
  const { taskKey, submission } = req.body || {};
  const u = req.user;
  if (!u.testPassed) return res.status(403).json({ error: 'Pass the typing test first.' });
  if (!u.tier || !PACKAGES[u.tier]) return res.status(403).json({ error: 'Unlock a package first to submit tasks.', needsPackage: true });
  const data = db.load();
  const today = new Date().toISOString().slice(0, 10);
  const [day] = String(taskKey || '').split(':');
  if (day !== today) return res.status(400).json({ error: 'That task has expired. New tasks arrive daily.' });
  if (data.assignments.some(a => a.userId === u.id && a.taskKey === taskKey)) {
    return res.status(409).json({ error: 'You already submitted this task today.' });
  }
  if (!submission || String(submission).trim().length < 20) {
    return res.status(400).json({ error: 'Your submission is too short — add a note or link to your delivered work (min 20 characters).' });
  }
  const tasks = dailyTasksFor(u.id, 16, payForTierFactory(u));
  const task = tasks.find(x => x.key === taskKey);
  if (!task) return res.status(404).json({ error: 'Task not found.' });
  // Auto-approve at demo scale; flag for admin review too.
  const fee = Math.round(task.pay * (db.load().settings.platformFeePct / 100));
  const net = task.pay - fee;
  data.assignments.unshift({ id: db.uid('asg'), userId: u.id, taskKey, day: today, title: task.title, category: task.category, gross: task.pay, fee, net, status: 'approved', submission: String(submission).slice(0, 2000), at: Date.now() });
  addTx(u.id, 'earning', net, `Task: ${task.title} (gross KES ${task.pay}, platform fee KES ${fee})`);
  notify(u.id, `Task approved — KES ${net} added to your wallet.`, 'success');
  checkTierUpgrade(u, db.load());
  db.saveNow();
  res.json({ ok: true, earned: net, wallet: u.wallet });
});

app.get('/api/earnings', requireAuth, (req, res) => {
  const data = db.load();
  const mine = data.assignments.filter(a => a.userId === req.user.id);
  const today = new Date().toISOString().slice(0, 10);
  res.json({
    wallet: req.user.wallet,
    todayCount: mine.filter(a => a.day === today).length,
    totalEarned: mine.reduce((s, a) => s + a.net, 0),
    recent: mine.slice(0, 20),
    transactions: data.transactions.filter(t => t.userId === req.user.id).slice(0, 30)
  });
});

/* ------------------------------- packages ---------------------------------- */

app.get('/api/packages', requireAuth, (req, res) => {
  const data = db.load();
  const earned = lifetimeEarned(data, req.user.id);
  const owned = req.user.unlockedPackages || [];
  const ordered = Object.entries(PACKAGES).sort((a, b) => a[1].order - b[1].order);
  res.json({
    tier: req.user.tier,
    earned,
    verified: !!req.user.verified,
    verificationPrice: VERIFICATION_PRICE,
    packages: ordered.map(([key, p]) => ({
      key, name: p.name, order: p.order, color: p.color, tagline: p.tagline,
      tasksPerDay: p.tasksPerDay, payPerTask: p.payPerTask,
      daily: p.tasksPerDay * p.payPerTask,
      price: p.price,
      unlocked: owned.indexOf(key) !== -1,
      current: req.user.tier === key
    }))
  });
});

/* Set the ACTIVE package (only among packages the user has already unlocked). */
app.post('/api/packages/activate', requireAuth, (req, res) => {
  const key = (req.body || {}).key;
  const u = req.user;
  if (!PACKAGES[key]) return res.status(400).json({ error: 'Unknown package.' });
  if (!hasUnlockedPackage(u, key)) return res.status(403).json({ error: 'Unlock this package first.' });
  u.tier = key;
  const p = PACKAGES[key];
  notify(u.id, `Active package switched to ${p.name}. Your daily drop now pays KES ${p.payPerTask} per gig.`, 'success');
  db.saveNow();
  res.json({ ok: true, user: publicUser(u) });
});

/* --------------------------------- wallet ---------------------------------- */

app.post('/api/wallet/deposit', requireAuth, (req, res) => {
  const { amount, mpesaRef } = req.body || {};
  const amt = Math.floor(Number(amount));
  if (!amt || amt < 50) return res.status(400).json({ error: 'Minimum deposit is KES 50.' });
  if (!mpesaRef || String(mpesaRef).trim().length < 6) {
    return res.status(400).json({ error: 'Enter your M-Pesa confirmation code for the deposit.' });
  }
  const data = db.load();
  data.deposits = data.deposits || [];
  data.deposits.unshift({ id: db.uid('dep'), userId: req.user.id, amount: amt, ref: String(mpesaRef).trim(), status: 'pending', at: Date.now() });
  notify(req.user.id, `Deposit of KES ${amt} received (ref ${String(mpesaRef).trim()}). It will reflect in your earnings wallet once confirmed.`, 'info');
  db.save();
  res.json({ ok: true });
});

/* ----------------------------- investor funds ------------------------------ */

app.get('/api/invest', requireAuth, (req, res) => {
  const u = req.user;
  const now = Date.now();
  const investments = (u.investments || []).map(x => ({
    ...x,
    planName: (INVEST_PLANS.find(p => p.id === x.planId) || {}).name || x.planId,
    matured: now >= x.maturesAt
  }));
  const active = investments.filter(i => i.status === 'active');
  res.json({
    plans: INVEST_PLANS,
    wallet: u.wallet,
    investBalance: active.reduce((s, i) => s + i.amount, 0),
    projected: active.reduce((s, i) => s + i.amount + i.interest, 0),
    investments: investments.slice(0, 40)
  });
});

app.post('/api/invest/deposit', requireAuth, (req, res) => {
  const { planId, amount } = req.body || {};
  const plan = INVEST_PLANS.find(p => p.id === planId);
  if (!plan) return res.status(400).json({ error: 'Choose a valid plan.' });
  const amt = Math.floor(Number(amount));
  if (!amt || amt < 100) return res.status(400).json({ error: 'Minimum investment is KES 100.' });
  const data = db.load();
  const u = req.user;
  if (amt > u.wallet) return res.status(400).json({ error: 'Insufficient earnings-wallet balance. Top up via Wallet then Deposit first.' });
  const interest = Math.round(amt * plan.rate);
  u.wallet = Math.round((u.wallet - amt) * 100) / 100;
  data.transactions.unshift({ id: db.uid('tx'), userId: u.id, type: 'invest', amount: -amt, note: `Moved to Investor Funds — ${plan.name}`, at: Date.now(), balanceAfter: u.wallet });
  u.investments = u.investments || [];
  const maturesAt = Date.now() + plan.days * 86400000;
  u.investments.unshift({ id: db.uid('inv'), planId: plan.id, amount: amt, interest, startAt: Date.now(), maturesAt, status: 'active' });
  notify(u.id, `KES ${amt} invested in the ${plan.name}. On ${new Date(maturesAt).toLocaleDateString('en-KE')} you can withdraw KES ${amt + interest} to your earnings wallet.`, 'success');
  db.saveNow();
  res.json({ ok: true, wallet: u.wallet });
});

app.post('/api/invest/withdraw/:id', requireAuth, (req, res) => {
  const u = req.user;
  const inv = (u.investments || []).find(x => x.id === req.params.id);
  if (!inv) return res.status(404).json({ error: 'Investment not found.' });
  if (inv.status !== 'active') return res.status(400).json({ error: 'This investment was already withdrawn.' });
  if (Date.now() < inv.maturesAt) {
    const daysLeft = Math.ceil((inv.maturesAt - Date.now()) / 86400000);
    return res.status(400).json({ error: `Plan not matured yet — ${daysLeft} day(s) remaining. Funds unlock on ${new Date(inv.maturesAt).toLocaleDateString('en-KE')}.` });
  }
  inv.status = 'withdrawn';
  inv.withdrawnAt = Date.now();
  addTx(u.id, 'invest_return', inv.amount + inv.interest, `Investor Funds payout — principal KES ${inv.amount} + return KES ${inv.interest}`);
  notify(u.id, `Investor Funds payout: KES ${inv.amount + inv.interest} moved to your earnings wallet.`, 'success');
  db.saveNow();
  res.json({ ok: true, wallet: u.wallet });
});

app.post('/api/wallet/withdraw', requireAuth, (req, res) => {
  const { amount, phone } = req.body || {};
  const amt = Math.floor(Number(amount));
  const data = db.load();
  const u = req.user;
  const min = data.settings.minWithdrawal;
  if (!amt || amt < min) return res.status(400).json({ error: `Minimum withdrawal is KES ${min}.` });
  if (amt > u.wallet) return res.status(400).json({ error: 'Insufficient balance.' });
  if (!phone || !/^(\+?254|0)\d{9}$/.test(String(phone).replace(/\s/g, ''))) {
    return res.status(400).json({ error: 'Enter a valid M-Pesa phone number (e.g. 0712345678).' });
  }
  addTx(u.id, 'withdrawal', -amt, `Withdrawal to M-Pesa ${phone} (pending approval)`);
  const data2 = db.load();
  data2.withdrawals = data2.withdrawals || [];
  data2.withdrawals.unshift({ id: db.uid('wd'), userId: u.id, amount: amt, phone: String(phone), status: 'pending', at: Date.now() });
  notify(u.id, `Withdrawal of KES ${amt} received and sent for approval. Track its status (pending → approved → cleared) in your Wallet.`, 'info');
  db.saveNow();
  res.json({ ok: true, wallet: u.wallet });
});

/* User tracks their own withdrawal requests: pending → approved → cleared. */
app.get('/api/wallet/withdrawals', requireAuth, (req, res) => {
  const data = db.load();
  const mine = (data.withdrawals || []).filter(w => w.userId === req.user.id);
  res.json({ withdrawals: mine.slice(0, 30) });
});

/* ------------------------------- marketplace ------------------------------- */

app.post('/api/gigs', requireAuth, (req, res) => {
  const { title, category, price, description } = req.body || {};
  if (!title || !category || !price) return res.status(400).json({ error: 'Title, category and price are required.' });
  const data = db.load();
  const gig = { id: db.uid('gig'), userId: req.user.id, userName: req.user.name, verified: req.user.verified, title: String(title).slice(0, 90), category: String(category), price: Math.max(50, Math.floor(Number(price))), description: String(description || '').slice(0, 800), active: true, at: Date.now() };
  data.gigs.unshift(gig);
  db.save();
  res.json({ ok: true, gig });
});

app.get('/api/gigs', (req, res) => {
  const data = db.load();
  const q = String(req.query.q || '').toLowerCase();
  let gigs = data.gigs.filter(g => g.active);
  if (q) gigs = gigs.filter(g => (g.title + g.category + g.description).toLowerCase().includes(q));
  res.json({ gigs: gigs.slice(0, 60) });
});

app.delete('/api/gigs/:id', requireAuth, (req, res) => {
  const data = db.load();
  const g = data.gigs.find(x => x.id === req.params.id && x.userId === req.user.id);
  if (!g) return res.status(404).json({ error: 'Gig not found.' });
  g.active = false;
  db.save();
  res.json({ ok: true });
});

app.post('/api/orders', requireAuth, (req, res) => {
  const { gigId, brief } = req.body || {};
  const data = db.load();
  const g = data.gigs.find(x => x.id === gigId && x.active);
  if (!g) return res.status(404).json({ error: 'Gig not found.' });
  if (g.userId === req.user.id) return res.status(400).json({ error: 'You cannot order your own gig.' });
  const fee = Math.round(g.price * (data.settings.platformFeePct / 100));
  const order = { id: db.uid('ord'), gigId, gigTitle: g.title, buyerId: req.user.id, buyerName: req.user.name, sellerId: g.userId, price: g.price, fee, status: 'in_progress', brief: String(brief || '').slice(0, 1000), at: Date.now() };
  data.orders.unshift(order);
  notify(g.userId, `New order: "${g.title}" (KES ${g.price}). Check your Orders tab.`, 'order');
  db.save();
  res.json({ ok: true, order });
});

app.get('/api/orders', requireAuth, (req, res) => {
  const data = db.load();
  res.json({
    buying: data.orders.filter(o => o.buyerId === req.user.id).slice(0, 30),
    selling: data.orders.filter(o => o.sellerId === req.user.id).slice(0, 30)
  });
});

app.post('/api/orders/:id/complete', requireAuth, (req, res) => {
  const data = db.load();
  const o = data.orders.find(x => x.id === req.params.id);
  if (!o) return res.status(404).json({ error: 'Order not found.' });
  if (o.buyerId !== req.user.id && o.sellerId !== req.user.id) return res.status(403).json({ error: 'Not your order.' });
  if (o.status !== 'in_progress') return res.status(400).json({ error: 'Order already closed.' });
  o.status = 'completed';
  o.completedAt = Date.now();
  addTx(o.sellerId, 'earning', o.price - o.fee, `Order completed: "${o.gigTitle}" (gross KES ${o.price}, fee KES ${o.fee})`);
  notify(o.buyerId, `Order "${o.gigTitle}" marked complete. Asante!`, 'success');
  const seller = db.load().users.find(x => x.id === o.sellerId);
  if (seller) checkTierUpgrade(seller, db.load());
  db.saveNow();
  res.json({ ok: true });
});

/* ----------------------------- notifications ------------------------------- */

app.get('/api/notifications', requireAuth, (req, res) => {
  const data = db.load();
  const mine = data.notifications.filter(n => n.userId === req.user.id).slice(0, 30);
  res.json({ notifications: mine, unread: mine.filter(n => !n.read).length });
});
app.post('/api/notifications/read', requireAuth, (req, res) => {
  const data = db.load();
  data.notifications.forEach(n => { if (n.userId === req.user.id) n.read = true; });
  db.save();
  res.json({ ok: true });
});

/* --------------------------------- admin ----------------------------------- */

app.post('/api/admin/login', (req, res) => {
  if ((req.body || {}).password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password.' });
  res.json({ ok: true, key: ADMIN_PASSWORD });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const data = db.load();
  res.json({
    users: data.users.length,
    verified: data.users.filter(u => u.verified).length,
    testsPassed: data.users.filter(u => u.testPassed).length,
    assignments: data.assignments.length,
    orders: data.orders.length,
    gigs: data.gigs.filter(g => g.active).length,
    pendingWithdrawals: (data.withdrawals || []).filter(w => w.status === 'pending').length,
    pendingDeposits: (data.deposits || []).filter(d => d.status === 'pending').length,
    activeInvestments: data.users.reduce((s, u) => s + (u.investments || []).filter(i => i.status === 'active').length, 0),
    totalInvested: data.users.reduce((s, u) => s + (u.investments || []).filter(i => i.status === 'active').reduce((a, i) => a + i.amount, 0), 0),
    totalPaidOut: data.transactions.filter(t => t.type === 'earning').reduce((s, t) => s + t.amount, 0),
    feesCollected: data.assignments.reduce((s, a) => s + (a.fee || 0), 0) + data.orders.filter(o => o.status === 'completed').reduce((s, o) => s + o.fee, 0)
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const data = db.load();
  res.json({ users: data.users.map(u => ({ id: u.id, name: u.name, email: u.email, wallet: u.wallet, tier: u.tier, verified: u.verified, testPassed: u.testPassed, suspended: u.suspended, createdAt: u.createdAt })) });
});

app.post('/api/admin/users/:id/tier', requireAdmin, (req, res) => {
  const data = db.load();
  const u = data.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  const tier = (req.body || {}).tier;
  if (!PACKAGES[tier]) return res.status(400).json({ error: 'Invalid package.' });
  u.tier = tier;
  db.save();
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/suspend', requireAdmin, (req, res) => {
  const data = db.load();
  const u = data.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  u.suspended = !!(req.body || {}).suspended;
  db.save();
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/adjust', requireAdmin, (req, res) => {
  const amt = Number((req.body || {}).amount);
  if (!amt) return res.status(400).json({ error: 'Amount required.' });
  const tx = addTx(req.params.id, 'admin_adjustment', amt, (req.body || {}).note || 'Admin adjustment');
  if (!tx) return res.status(404).json({ error: 'User not found.' });
  db.saveNow();
  res.json({ ok: true, tx });
});

app.get('/api/admin/withdrawals', requireAdmin, (req, res) => {
  const data = db.load();
  res.json({ withdrawals: (data.withdrawals || []).slice(0, 100) });
});

/* Withdrawal lifecycle: pending → approved (admin okays it) → cleared (admin has sent
   the money manually from their phone). 'rejected' refunds the wallet. 'paid' is kept
   as a backward-compatible alias of 'cleared'. */
app.post('/api/admin/withdrawals/:id', requireAdmin, (req, res) => {
  const data = db.load();
  const w = (data.withdrawals || []).find(x => x.id === req.params.id);
  if (!w) return res.status(404).json({ error: 'Not found.' });
  let next = String((req.body || {}).status || '');
  if (next === 'paid') next = 'cleared';
  if (['approved', 'cleared', 'rejected'].indexOf(next) === -1) return res.status(400).json({ error: 'Invalid status.' });
  if (w.status === 'cleared' || w.status === 'paid') return res.status(400).json({ error: 'Already cleared — money was sent.' });
  if (w.status === 'rejected') return res.status(400).json({ error: 'Already rejected and refunded.' });
  if (next === 'approved') {
    if (w.status !== 'pending') return res.status(400).json({ error: 'Only pending requests can be approved.' });
    w.status = 'approved';
    w.approvedAt = Date.now();
    notify(w.userId, `Your withdrawal of KES ${w.amount} was approved ✅ — the payout is being sent to M-Pesa ${w.phone}.`, 'success');
  } else if (next === 'cleared') {
    w.status = 'cleared';
    w.clearedAt = Date.now();
    notify(w.userId, `Your withdrawal of KES ${w.amount} has been SENT to M-Pesa ${w.phone} 💸. Check your phone — asante!`, 'success');
  } else {
    w.status = 'rejected';
    w.rejectedAt = Date.now();
    addTx(w.userId, 'refund', w.amount, 'Withdrawal rejected — funds returned');
    notify(w.userId, `Your withdrawal of KES ${w.amount} was rejected and the funds were returned to your earnings wallet. Contact support if unsure.`, 'info');
  }
  db.saveNow();
  res.json({ ok: true });
});

app.get('/api/admin/assignments', requireAdmin, (req, res) => {
  const data = db.load();
  res.json({ assignments: data.assignments.slice(0, 100) });
});

app.get('/api/admin/deposits', requireAdmin, (req, res) => {
  const data = db.load();
  res.json({ deposits: (data.deposits || []).slice(0, 100) });
});

app.post('/api/admin/deposits/:id', requireAdmin, (req, res) => {
  const data = db.load();
  const d = (data.deposits || []).find(x => x.id === req.params.id);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  if (d.status !== 'pending') return res.status(400).json({ error: 'Already processed.' });
  d.status = (req.body || {}).status === 'approved' ? 'approved' : 'rejected';
  if (d.status === 'approved') {
    addTx(d.userId, 'deposit', d.amount, `M-Pesa deposit confirmed (ref ${d.ref})`);
    notify(d.userId, `Your deposit of KES ${d.amount} has been confirmed and added to your earnings wallet.`, 'success');
  } else {
    notify(d.userId, `Your deposit of KES ${d.amount} (ref ${d.ref}) could not be confirmed. Please contact support.`, 'info');
  }
  db.saveNow();
  res.json({ ok: true });
});

/* ------------------------- KCB Buni M-Pesa STK push -------------------------- */

const KCB = {
  key: process.env.KCB_CONSUMER_KEY || '',
  secret: process.env.KCB_CONSUMER_SECRET || '',
  tokenUrl: process.env.KCB_TOKEN_ENDPOINT || 'https://api.buni.kcbgroup.com/token',
  stkUrl: process.env.KCB_STKPUSH_ENDPOINT || 'https://api.buni.kcbgroup.com/mm/api/request/1.0.0/stkpush',
  shortCode: process.env.KCB_SHORT_CODE || '522522',          // KCB shared short code
  passKey: process.env.KCB_PASSKEY || '',                     // empty when using the shared short code
  till: process.env.KCB_TILL_NUMBER || process.env.KCB_SHORT_CODE || '522522',
  // NB: KCB's gateway validates the callback URL case-sensitively — keep the host lowercase.
  baseUrl: (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || 'https://upworkkenyabackend.onrender.com').replace(/\/+$/, '').toLowerCase(),
  callbackUrl: process.env.CALLBACK_URL || '',
  // Demo mode: when consumer key/secret are missing, STK-push endpoints simulate a
  // successful transaction locally so the flow (enter number → enter PIN → confirm →
  // package unlocked / verified / deposited) still works end-to-end.
  demoMode: !(process.env.KCB_CONSUMER_KEY && process.env.KCB_CONSUMER_SECRET)
};

let kcbTokenCache = { value: null, expiresAt: 0 };

async function kcbAccessToken() {
  if (!KCB.key || !KCB.secret) throw new Error('KCB API credentials are not configured on the server.');
  if (kcbTokenCache.value && Date.now() < kcbTokenCache.expiresAt - 30000) return kcbTokenCache.value;
  const auth = Buffer.from(KCB.key + ':' + KCB.secret).toString('base64');
  const r = await fetch(KCB.tokenUrl + '?grant_type=client_credentials', {
    method: 'POST',
    headers: { Authorization: 'Basic ' + auth }
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || !data.access_token) {
    throw new Error(data.error_description || data.error || ('KCB token request failed (HTTP ' + r.status + ').'));
  }
  kcbTokenCache = { value: data.access_token, expiresAt: Date.now() + (Number(data.expires_in) || 3600) * 1000 };
  return kcbTokenCache.value;
}

/* Initiate an STK push. `purpose` decides what the successful payment unlocks:
     - 'deposit'  (default) → credits amount to the earnings wallet
     - 'package'  + packageKey → unlocks that earning package for the user
     - 'verify'   → activates the Verified badge (fixed KES 450)                */
app.post('/api/pay/kcb/stkpush', requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const purpose = ['deposit', 'package', 'verify'].indexOf(body.purpose) !== -1 ? body.purpose : 'deposit';
    let amt, packageKey = null;

    if (purpose === 'package') {
      packageKey = String(body.packageKey || '');
      if (!PACKAGES[packageKey]) return res.status(400).json({ error: 'Choose a valid package to unlock.' });
      if (hasUnlockedPackage(req.user, packageKey)) return res.status(400).json({ error: 'You have already unlocked this package.' });
      amt = PACKAGES[packageKey].price;
    } else if (purpose === 'verify') {
      if (req.user.verified) return res.status(400).json({ error: 'Your account is already verified.' });
      amt = VERIFICATION_PRICE;
    } else {
      amt = Math.floor(Number(body.amount));
      if (!amt || amt < 1) return res.status(400).json({ error: 'Enter a valid amount (minimum KES 1).' });
    }
    if (amt > 300000) return res.status(400).json({ error: 'Amount exceeds the M-Pesa transaction limit.' });

    let phone = String(body.phone || '').replace(/[\s+\-()]/g, '');
    if (/^0\d{9}$/.test(phone)) phone = '254' + phone.slice(1);
    if (!/^254\d{9}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid M-Pesa phone number (e.g. 0712345678).' });

    const data = db.load();
    data.payments = data.payments || [];
    const ref = ('UPW' + String(req.user.id).slice(-4) + Date.now().toString(36)).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    const invoiceNumber = KCB.till + '#' + ref;
    const payment = {
      id: db.uid('pay'), userId: req.user.id, amount: amt, phone, reference: ref, invoiceNumber,
      purpose, packageKey,
      status: 'pending', resultCode: null, resultDesc: '', mpesaReceipt: '',
      merchantRequestId: '', checkoutRequestId: '', createdAt: Date.now(), updatedAt: Date.now()
    };
    data.payments.unshift(payment);
    db.save();

    // Demo mode: no real KCB credentials configured — simulate the PIN prompt and
    // auto-confirm the payment after a short delay so the end-to-end flow works.
    if (KCB.demoMode) {
      payment.merchantRequestId = 'DEMO-' + ref;
      payment.checkoutRequestId = 'DEMO-CO-' + ref;
      payment.resultDesc = 'M-Pesa PIN prompt sent to ' + phone + '. Enter your PIN to complete.';
      db.saveNow();
      setTimeout(() => finalizePayment(payment.id, 0, 'The service request is processed successfully.', 'MDX' + ref.slice(-6)), 2500);
      return res.json({ ok: true, paymentId: payment.id, message: payment.resultDesc, demo: true });
    }

    const jwt = await kcbAccessToken();
    const r = await fetch(KCB.stkUrl, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + jwt, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        phoneNumber: phone,
        amount: String(amt),
        invoiceNumber: invoiceNumber,
        sharedShortCode: true,
        orgShortCode: KCB.shortCode,
        orgPassKey: KCB.passKey,
        callbackUrl: KCB.callbackUrl || (KCB.baseUrl + '/api/pay/kcb/callback'),
        transactionDescription: 'Upwork Kenya'
      })
    });
    const out = await r.json().catch(() => ({}));
    // KCB Buni wraps the payload as { header:{statusCode,statusDescription}, response:{MerchantRequestID,CheckoutRequestID,ResponseCode,...} }
    const hdr = out.header || {};
    const kcbResp = out.response || out;
    payment.gatewayResponse = out;
    payment.merchantRequestId = kcbResp.MerchantRequestID || kcbResp.merchantRequestID || '';
    payment.checkoutRequestId = kcbResp.CheckoutRequestID || kcbResp.checkoutRequestID || '';
    payment.updatedAt = Date.now();

    const headerCode = hdr.statusCode !== undefined ? String(hdr.statusCode) : '';
    const initCode = kcbResp.ResponseCode !== undefined ? String(kcbResp.ResponseCode) : (headerCode || (r.ok ? '0' : '1'));
    const accepted = r.ok && (initCode === '0' || headerCode === '0') && (payment.checkoutRequestId || payment.merchantRequestId);
    if (!accepted) {
      payment.status = 'failed';
      payment.resultDesc = kcbResp.ResponseDescription || kcbResp.CustomerMessage || hdr.statusDescription || kcbResp.errorMessage || kcbResp.message || ('KCB request failed (HTTP ' + r.status + ').');
      db.saveNow();
      return res.status(502).json({ error: payment.resultDesc });
    }
    payment.resultDesc = kcbResp.ResponseDescription || kcbResp.CustomerMessage || hdr.statusDescription || 'STK push sent.';
    db.saveNow();
    res.json({ ok: true, paymentId: payment.id, message: payment.resultDesc });
  } catch (e) {
    console.error('[kcb] stkpush error:', e.message);
    res.status(502).json({ error: e.message || 'Could not reach the payment gateway. Try again.' });
  }
});

/* Client polls this for the live status of an STK request. */
app.get('/api/pay/kcb/status/:id', requireAuth, (req, res) => {
  const data = db.load();
  const p = (data.payments || []).find(x => x.id === req.params.id && x.userId === req.user.id);
  if (!p) return res.status(404).json({ error: 'Payment not found.' });
  res.json({ id: p.id, status: p.status, amount: p.amount, resultCode: p.resultCode, resultDesc: p.resultDesc, mpesaReceipt: p.mpesaReceipt, wallet: req.user.wallet });
});

/* Manual confirmation fallback: if the user already received the M-Pesa confirmation
   SMS from Safaricom/KCB but the gateway callback never arrived (site showed 'timeout'),
   they enter the receipt code from the SMS and the payment completes INSTANTLY. */
app.post('/api/pay/kcb/confirm', requireAuth, (req, res) => {
  const { paymentId, receipt } = req.body || {};
  const data = db.load();
  const p = (data.payments || []).find(x => x.id === String(paymentId || '') && x.userId === req.user.id);
  if (!p) return res.status(404).json({ error: 'Payment not found.' });
  if (p.status === 'success') return res.json({ ok: true, status: 'success' });
  const code = String(receipt || '').trim().toUpperCase();
  if (!/^[A-Z0-9]{6,20}$/.test(code)) return res.status(400).json({ error: 'Enter the exact M-Pesa confirmation code from the SMS (e.g. QGH1ABC2XY).' });
  if ((data.payments || []).some(x => x.mpesaReceipt && x.mpesaReceipt === code && x.id !== p.id)) {
    return res.status(409).json({ error: 'That confirmation code was already used for another payment.' });
  }
  finalizePayment(p.id, 0, 'Confirmed manually with M-Pesa receipt ' + code, code);
  res.json({ ok: true, status: 'success' });
});

/* Central success/failure handler used by both the KCB callback and the demo simulator. */
function finalizePayment(paymentId, code, desc, receipt, amount) {
  const data = db.load();
  const p = (data.payments || []).find(x => x.id === paymentId);
  if (!p || p.status === 'success') return;
  p.resultCode = Number.isNaN(code) ? null : code;
  p.resultDesc = desc || '';
  p.updatedAt = Date.now();

  if (code === 0) {
    p.mpesaReceipt = receipt || p.mpesaReceipt || '';
    const paid = Number(amount) || p.amount;
    p.status = 'success';
    const u = data.users.find(x => x.id === p.userId);
    if (!u) { db.saveNow(); return; }

    if (p.purpose === 'package') {
      const pkg = PACKAGES[p.packageKey];
      if (pkg) {
        u.unlockedPackages = u.unlockedPackages || [];
        if (u.unlockedPackages.indexOf(p.packageKey) === -1) u.unlockedPackages.push(p.packageKey);
        // Auto-activate this package if it's the highest the user owns.
        checkTierUpgrade(u);
        addTx(u.id, 'package_unlock', 0, `Unlocked ${pkg.name} package — M-Pesa ${p.mpesaReceipt || p.reference} (KES ${paid} paid)`);
        notify(u.id, `🎉 ${pkg.name} package unlocked! You now receive ${pkg.tasksPerDay} tasks/day at KES ${pkg.payPerTask} each. Head to Today's Tasks to start earning.`, 'success');
      }
    } else if (p.purpose === 'verify') {
      u.verified = true;
      u.verificationRef = p.mpesaReceipt || p.reference;
      addTx(u.id, 'verification', 0, `Verified badge activated — M-Pesa ${p.mpesaReceipt || p.reference} (KES ${paid} paid)`);
      notify(u.id, '✓ You are now a Verified freelancer! The blue badge is on your profile, and you get +1 task/day and +15% pay boost.', 'success');
    } else {
      addTx(u.id, 'deposit', paid, 'M-Pesa deposit via STK push (receipt ' + (p.mpesaReceipt || '—') + ', ref ' + p.reference + ')');
      data.deposits = data.deposits || [];
      data.deposits.unshift({ id: db.uid('dep'), userId: u.id, amount: paid, ref: p.mpesaReceipt || p.reference, status: 'approved', at: Date.now(), method: 'kcb_stk' });
      notify(u.id, 'Deposit of KES ' + paid + ' confirmed via M-Pesa (receipt ' + (p.mpesaReceipt || '—') + '). Your earnings wallet has been credited.', 'success');
    }
  } else if (code === 1032) p.status = 'cancelled';
  else if (code === 1037) p.status = 'timeout';
  else p.status = 'failed';

  db.saveNow();
}

/* KCB calls this with the final result (success / cancelled / timeout / failed). */
app.post('/api/pay/kcb/callback', (req, res) => {
  try {
    const body = req.body || {};
    let cb = ((body.Body || {}).stkCallback) || body.stkCallback || {};
    if (cb.ResultCode === undefined && body.response && body.response.ResultCode !== undefined) cb = body.response;
    const merchantId = cb.MerchantRequestID || '';
    const checkoutId = cb.CheckoutRequestID || '';
    const code = Number(cb.ResultCode);
    const desc = cb.ResultDesc || '';
    const data = db.load();
    const p = (data.payments || []).find(x =>
      (merchantId && x.merchantRequestId === merchantId) || (checkoutId && x.checkoutRequestId === checkoutId)
    );
    if (p) {
      let receipt = '';
      let paidAmount;
      if (code === 0) {
        const items = (((cb.CallbackMetadata || {}).Item) || []);
        const get = n => { const it = items.find(i => i.Name === n); return it ? it.Value : undefined; };
        receipt = get('MpesaReceiptNumber') || '';
        paidAmount = Number(get('Amount'));
      }
      finalizePayment(p.id, code, desc, receipt, paidAmount);
    }
  } catch (e) {
    console.error('[kcb] callback error:', e.message);
  }
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
});

/* --------------------------------- health ----------------------------------- */

/* Used by the frontend/admin keep-alive ping (every 10 min) so the free-tier
   server and the Neon connection never sleep; also handy for uptime checks. */
app.get('/api/health', async (req, res) => {
  let pg = false;
  try { pg = await db.ping(); } catch {}
  res.json({ ok: true, db: pg ? 'neon-postgres' : 'local-json', at: Date.now() });
});

/* --------------------------------- startup --------------------------------- */

(async () => {
  try { await db.init(); } catch (e) { console.error('[db] init error:', e.message); }
  app.listen(PORT, () => console.log(`Upwork Kenya running on port ${PORT}`));
})();
