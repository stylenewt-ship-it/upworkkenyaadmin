# Upwork Kenya 🇰🇪

A freelance task marketplace for Kenya — daily gigs in writing, design, data entry, analysis and more, with a real-time wallet, M-Pesa withdrawal flow, marketplace orders, verified badges, and a secured admin panel.

**Model:** clients pay for completed work; the platform earns a flat 10% service fee. Freelancers never pay to access tasks.

## Run locally

```bash
npm install
npm start          # http://localhost:3000
```

## Deploy on Render

1. Push this folder to a GitHub repo.
2. On Render → **New → Web Service** → connect the repo.
3. Settings (mostly auto-detected):
   - **Build command:** `npm install`
   - **Start command:** `node server.js`
   - **Environment variables:**
     - `NODE_VERSION` = `20.18.0`
     - `ADMIN_PASSWORD` = your admin password (default `11upwork72` if unset)
     - `SESSION_SECRET` = any long random string
4. Deploy. Your site is live at `https://<your-app>.onrender.com`.

> The database is **Neon Postgres** (serverless PostgreSQL) — set `DATABASE_URL` and all state (users, sessions, wallets, packages, payments) becomes durable: logins and data survive restarts, redeploys and Render's ephemeral disk. A local `data/db.json` mirror is kept as a boot fallback, so the app still runs if the database is briefly unreachable.

## Admin panel

- URL: `https://<your-app>.onrender.com/admin`
- Password: value of `ADMIN_PASSWORD` (default `11upwork72`)
- Manage users (tiers, suspend, wallet adjustments), approve/reject withdrawals, review task submissions, view platform stats.

## Pages

| Route | Purpose |
|---|---|
| `/` | Landing page |
| `/register.html` | Create account |
| `/login.html` | Log in |
| `/forgot.html` / `/reset.html` | Password reset |
| `/app.html` | Member dashboard (tasks, wallet, marketplace, orders, profile, settings) |
| `/admin` | Admin panel |

## Notes for production

- Password reset currently returns the reset link in the response (free hosting has no SMTP). Connect an email service (e.g. SendGrid/Resend) and email the link instead.
- M-Pesa verification is confirmed by entering the transaction code manually; wire in the Daraja API for automatic confirmation.
- State is stored as a single JSONB document in Neon Postgres (table `kv_store`). To reset the platform, delete that row and restart.
