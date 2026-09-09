'use strict';

/**
 * Upwork Kenya - JSON file datastore (pure JavaScript, zero native deps).
 * Data is persisted to data/db.json. On Render free tier the disk is
 * ephemeral, so a background backup interval keeps the write window small.
 */

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

function seedData() {
  const now = Date.now();
  return {
    meta: { version: 1, seededAt: now },
    users: [],
    sessions: {},          // token -> { userId, createdAt }
    resetTokens: {},       // token -> { email, expiresAt }
    tasks: [],             // available task pool
    assignments: [],       // user task assignments
    orders: [],            // client orders placed with freelancers
    transactions: [],      // wallet movements
    notifications: [],
    adminLogs: [],
    gigs: [],              // freelancer storefront gigs
    deposits: [],          // M-Pesa deposits awaiting admin confirmation
    settings: {
      platformFeePct: 10,
      verificationFee: 450,
      minWithdrawal: 100
    }
  };
}

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

let cache = null;

function load() {
  if (cache) return cache;
  ensureDir();
  if (fs.existsSync(DB_FILE)) {
    try {
      cache = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) {
      const corrupt = DB_FILE + '.corrupt-' + Date.now();
      fs.copyFileSync(DB_FILE, corrupt);
      cache = seedData();
      save();
    }
  } else {
    cache = seedData();
    save();
  }
  return cache;
}

let saveTimer = null;
function save() {
  ensureDir();
  if (saveTimer) return; // debounce bursts
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(cache, null, 2));
      fs.renameSync(DB_FILE + '.tmp', DB_FILE);
    } catch (e) {
      console.error('[db] save failed:', e.message);
    }
  }, 60);
}

function saveNow() {
  ensureDir();
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(cache, null, 2));
  fs.renameSync(DB_FILE + '.tmp', DB_FILE);
}

function uid(prefix) {
  return (prefix || 'id') + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

module.exports = { load, save, saveNow, uid, DB_FILE };
