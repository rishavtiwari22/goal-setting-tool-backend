# SMART Goal Coach — Backend

Express + MongoDB REST API for the SMART Goal Coach app.

## Local Development

```bash
npm install
cp .env.example .env   # fill in your values
npm run dev            # starts with --watch (auto-restart on changes)
```

Server runs at `http://localhost:3001`.

Health check: `GET /health`

---

## Environment Variables

See [.env.example](.env.example) for all required variables.

| Variable       | Description |
|---------------|-------------|
| `MONGO_URI`   | MongoDB Atlas connection string |
| `PORT`        | Port to listen on (default: 3001) |
| `JWT_SECRET`  | Long random secret for signing JWTs — generate with `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
| `SMTP_HOST`   | SMTP server (e.g. `smtp.gmail.com`) |
| `SMTP_PORT`   | SMTP port (587 for Gmail) |
| `SMTP_USER`   | Gmail address |
| `SMTP_PASS`   | Gmail **App Password** (not your real password) |
| `FROM_EMAIL`  | Sender display email |
| `FRONTEND_URL`| Your frontend URL (used in email links + CORS) |

---

## Deploy to Render

1. Push this repo to GitHub.
2. Go to [render.com](https://render.com) → **New → Web Service**
3. Connect your GitHub repo.
4. Settings:
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. Add all environment variables from `.env.example` in Render's **Environment** tab.
6. Click **Deploy**.

Render gives you a URL like `https://smart-backend-xxxx.onrender.com`.

---

## Deploy to Railway

1. Push to GitHub.
2. Go to [railway.app](https://railway.app) → **New Project → Deploy from GitHub repo**.
3. Add environment variables in the **Variables** tab.
4. Railway auto-detects Node and runs `npm start`.

---

## API Endpoints

### Auth
| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/api/auth/signup` | `{ email, password, name }` | Create account |
| POST | `/api/auth/login` | `{ email, password }` | Login, returns JWT |
| GET | `/api/auth/me` | — (JWT required) | Get current user |
| POST | `/api/auth/forgot-password` | `{ email }` | Send reset email |
| POST | `/api/auth/reset-password` | `{ email, token, newPassword }` | Reset password |

### Daily Records (all require `Authorization: Bearer <token>`)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/daily-records?date=YYYY-MM-DD` | Get record(s) |
| POST | `/api/daily-records` | Create a record |
| PATCH | `/api/daily-records/:id/goals` | Update goals |
| PATCH | `/api/daily-records/:id/reflections` | Add reflection |

---

## Security Notes

- JWT secret must be set in env — server exits on startup if missing.
- Passwords hashed with bcrypt (cost factor 10).
- Reset tokens are SHA-256 hashed before storage; raw token only sent via email.
- Reset/resend endpoints are rate-limited (3 req/email/hour, in-memory).
- `tokenVersion` field on users invalidates all prior JWTs after a password reset.
