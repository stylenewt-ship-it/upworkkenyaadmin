# Upwork Kenya 🇰🇪

A freelance task marketplace for Kenya — daily gigs in writing, design, data entry, analysis and more, with a real-time wallet, M-Pesa withdrawal flow, marketplace orders, verified badges, and a secured admin panel.

**Model:** clients pay for completed work; the platform earns a flat 10% service fee. Freelancers never pay to access tasks.

## Run locally

```bash
cp .env.example .env   # fill in your own values
npm install
npm start              # http://localhost:3000
```

## Deploy on Render

1. Push this folder to a **private** GitHub repo.
2. On Render → **New → Web Service** → connect the repo.
3. Settings (mostly auto-detected):
   - **Build command:** `npm install`
   - **Start command:** `node server.js`
   - **Environment variables** (set these in the Render dashboard — never in code):

     | Variable | What to put |
     |---|---|
     | `NODE_VERSION` | `20.18.0` |
     | `ADMIN_PASSWORD` | A long random admin password you invent |
     | `SESSION_SECRET` | Any long random string (Render can auto-generate) |
     | `ADMIN_PATH` | A secret word for the admin URL, e.g. `manage-x7k2q9` |
     | `ALLOWED_ORIGINS` | Your frontend URL, e.g. `https://your-site.netlify.app` |
     | `DATABASE_URL` | Your Neon Postgres connection string |
     | `KCB_CONSUMER_KEY` / `KCB_CONSUMER_SECRET` | From KCB Buni (optional — demo mode without them) |

4. Deploy. Your API is live at `https://<your-app>.onrender.com`.

> The database is **Neon Postgres** (serverless PostgreSQL) — set `DATABASE_URL` and all state (users, sessions, wallets, packages, payments) becomes durable. A local `data/db.json` mirror is kept as a boot fallback.

## Admin panel

- URL: `https://<your-app>.onrender.com/<ADMIN_PATH>` — the path is the secret `ADMIN_PATH` value you set. Every other admin-looking URL returns 404.
- Log in with your `ADMIN_PASSWORD`. The password is exchanged for a short-lived server-side session token and is never stored in the browser.
- Manage users (tiers, suspend, wallet adjustments), approve/reject withdrawals, review task submissions, view platform stats.

## Frontend (Netlify)

The `frontend/` folder deploys to Netlify as a static site. After deploying the backend, edit **`frontend/js/config.js`** and set:

```js
window.UK_API_BASE = 'https://<your-app>.onrender.com';
```

## Security notes

- No secrets, passwords, database URLs or API keys exist anywhere in the code — everything comes from environment variables.
- CORS is locked to your `ALLOWED_ORIGINS` list; tokens travel in headers only (never in URLs).
- Login, register, password-reset, admin and payment endpoints are rate-limited.
- Right-click / DevTools shortcuts are disabled on the site and admin panel (casual-snooping deterrent).
- If you ever shared your old database URL or admin password (e.g. in a zip or screenshot), rotate them immediately — treat them as compromised.

## Notes for production

- Password reset: connect an email service (SendGrid/Resend) to email the reset link. For local testing only, set `ALLOW_DEV_RESET=true` to surface the reset token in the API response — never enable this in production.
- State is stored as a single JSONB document in Neon Postgres (table `kv_store`). To reset the platform, delete that row and restart.
