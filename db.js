'use strict';

/**
 * Upwork Kenya - durable datastore (Neon Postgres + local JSON fallback).
 *
 * The whole app state lives in one in-memory object (`cache`). Every save is
 * mirrored to:
 *   1. Neon Postgres (table `kv_store`, one JSONB row) — durable storage that
 *      survives restarts, redeploys and Render's ephemeral disk. This is what
 *      makes sessions/logins "immortal": the token still resolves after a
 *      restart because the session map is restored from Neon on boot.
 *   2. A local JSON file — fast boot fallback / offline mode.
 *
 * The public API (load / save / saveNow / uid) is intentionally UNCHANGED, so
 * no route logic anywhere else was touched.
 */

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

/* Neon Postgres connection comes ONLY from the DATABASE_URL environment
   variable — no credentials are stored anywhere in the code. Without it the
   app simply runs on the local JSON store.
   NOTE: node-postgres cannot negotiate `channel_binding=require`, so that
   parameter is stripped — sslmode=require still keeps the wire encrypted. */

function cleanUrl(u) {
  return String(u || '')
    .replace(/&?channel_binding=[^&]+/gi, '')
    .replace(/\?&/, '?')
    .replace(/\?$/, '');
}

function seedData() {
  const now = Date.now();
  return {
    meta: { version: 1, seededAt: now },
    users: [],
    sessions: {},          // token -> { userId, createdAt }
    adminSessions: {},     // admin token -> { createdAt, expiresAt } — persistent, 30-day sliding
    resetTokens: {},       // token -> { email, expiresAt }
    tasks: [],             // available task pool
    assignments: [],       // user task assignments
    orders: [],            // client orders placed with freelancers
    transactions: [],      // wallet movements
    notifications: [],
    adminLogs: [],
    gigs: [],              // freelancer storefront gigs
    deposits: [],          // M-Pesa deposits awaiting admin confirmation
    payments: [],          // STK-push payments (pending/success/failed)
    withdrawals: [],       // withdrawal requests
    settings: {
      platformFeePct: 10,
      verificationFee: 450,
      minWithdrawal: 100,
      withdrawalHoldDays: 7   // one withdrawal every 7 days; first withdrawal opens 7 days after joining
    }
  };
}

/* Fill any missing top-level keys so older saved states keep working. */
function ensureShape(d) {
  const s = seedData();
  if (!d || typeof d !== 'object') return s;
  for (const k of Object.keys(s)) if (d[k] === undefined) d[k] = s[k];
  d.settings = Object.assign({}, s.settings, d.settings || {});
  return d;
}

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

let cache = null;

/* ----------------------------- local JSON file ---------------------------- */

let saveTimer = null;

function saveLocal() {
  ensureDir();
  if (saveTimer) return; // debounce bursts
  saveTimer = setTimeout(() => {
    saveTimer = null;
    saveLocalNow();
  }, 60);
}

function saveLocalNow() {
  ensureDir();
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  try {
    fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(cache, null, 2));
    fs.renameSync(DB_FILE + '.tmp', DB_FILE);
  } catch (e) {
    console.error('[db] local save failed:', e.message);
  }
}

/* ------------------------------ Neon Postgres ----------------------------- */

let pgPool = null;
let pgReady = false;
let pgWriting = false;
let pgDirty = false;
let pgTimer = null;
let reconnectTimer = null;
let initPromise = null;
let firstSyncDone = false; // only the FIRST connect may pull state down from Neon

async function persistPg() {
  if (!pgReady || !pgPool || pgWriting) { if (pgReady) pgDirty = true; return; }
  pgWriting = true;
  try {
    await pgPool.query(
      `INSERT INTO kv_store (id, data, updated_at) VALUES ('main', $1::jsonb, now())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [JSON.stringify(cache)]
    );
  } catch (e) {
    pgReady = false;
    console.error('[db] Neon write failed (will reconnect):', e.message);
    scheduleReconnect();
  } finally {
    pgWriting = false;
    if (pgDirty) { pgDirty = false; persistPg(); }
  }
}

function queuePgPersist(immediate) {
  if (!pgReady) return;
  if (pgTimer && !immediate) return; // debounce bursts
  if (pgTimer) { clearTimeout(pgTimer); pgTimer = null; }
  pgTimer = setTimeout(() => { pgTimer = null; persistPg(); }, immediate ? 10 : 400);
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    initPromise = null;
    init().catch(() => {});
  }, 30000);
}

/**
 * Boot: load the local cache instantly, then connect to Neon. If Neon holds
 * state, THAT copy wins (it is the durable one) and is mirrored back to disk.
 * If Neon is empty (first ever boot), the local/seed state is pushed up.
 */
async function init() {
  load(); // local cache available immediately
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const url = cleanUrl(process.env.DATABASE_URL || '');
    if (!url) { console.log('[db] no DATABASE_URL — local JSON store only'); return; }
    try {
      if (pgPool) { try { await pgPool.end(); } catch {} pgPool = null; }
      const { Pool } = require('pg');
      pgPool = new Pool({
        connectionString: url,
        ssl: { rejectUnauthorized: false },
        max: 3,
        connectionTimeoutMillis: 10000,
        idleTimeoutMillis: 30000
      });
      await pgPool.query(`CREATE TABLE IF NOT EXISTS kv_store (
        id TEXT PRIMARY KEY,
        data JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
      const r = await pgPool.query(`SELECT data FROM kv_store WHERE id = 'main'`);
      const remote = r.rows && r.rows[0] && r.rows[0].data;
      if (remote && typeof remote === 'object' && Object.keys(remote).length && !firstSyncDone) {
        cache = ensureShape(remote);        // durable copy wins on FIRST boot — restores users/sessions/admin data after restarts, redeploys or data loss
        saveLocalNow();                     // mirror to disk for fast boots
        console.log('[db] state restored from Neon Postgres (' + (cache.users || []).length + ' users, ' + Object.keys(cache.sessions || {}).length + ' live sessions)');
      } else {
        // First-ever boot (Neon empty) OR a reconnect after a dropout: the local
        // in-memory state is the NEWEST copy — push it UP so Neon is restored to
        // the latest data instead of rolling the live app back to an older state.
        await pgPool.query(
          `INSERT INTO kv_store (id, data, updated_at) VALUES ('main', $1::jsonb, now())
           ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
          [JSON.stringify(cache)]
        );
        console.log(firstSyncDone ? '[db] reconnected — latest state pushed back up to Neon' : '[db] Neon Postgres seeded with the initial state');
      }
      firstSyncDone = true;
      pgReady = true;
      console.log('[db] connected to Neon Postgres — data is durable');
    } catch (e) {
      pgReady = false;
      console.error('[db] Neon connection failed — running on local JSON store:', e.message);
      scheduleReconnect();
    }
  })();
  return initPromise;
}

/* Health check used by /api/health — also keeps the Neon connection warm. */
async function ping() {
  if (!pgReady) { await init().catch(() => {}); return pgReady; }
  try { await pgPool.query('SELECT 1'); return true; }
  catch (e) { pgReady = false; scheduleReconnect(); return false; }
}

/* -------------------------------- public API ------------------------------ */

function load() {
  if (cache) return cache;
  ensureDir();
  if (fs.existsSync(DB_FILE)) {
    try {
      cache = ensureShape(JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
    } catch (e) {
      const corrupt = DB_FILE + '.corrupt-' + Date.now();
      fs.copyFileSync(DB_FILE, corrupt);
      cache = seedData();
      saveLocalNow();
    }
  } else {
    cache = seedData();
    saveLocalNow();
  }
  return cache;
}

function save() {
  saveLocal();
  queuePgPersist(false);
}

function saveNow() {
  saveLocalNow();
  queuePgPersist(true);
}

function uid(prefix) {
  return (prefix || 'id') + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

module.exports = { load, save, saveNow, uid, DB_FILE, init, ping, pgStatus: () => pgReady };
