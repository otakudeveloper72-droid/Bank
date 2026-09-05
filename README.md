# BBK Bank Portfolio Demo

A Flask + SQLite/PostgreSQL banking UI for portfolio/educational use.

> **Important:** This is a portfolio demo, not real banking software. Do not use it for real money, real customer data, or production financial services.

## Features

- Customer login with account number + PIN
- Customer dashboard, balance, transaction history and demo chart
- Deposits and withdrawals
- Staff authentication, with an optional "Remember this device" (a hashed
  device token in an HttpOnly cookie — the staff PIN itself is never stored)
- Staff account creation, customer/PIN verification and account closure
- Auto-save draft for the "open account" staff form (local browser draft only —
  never stores credentials)
- Customer "Remember this device" (remembers the account number only, in the
  browser; the PIN is never stored and full sign-in is always required)
- Live, database-backed analytics on the landing page: total accounts, total
  balance, account growth over time, and how long the database has been
  running (`GET /api/stats`, aggregate-only — no per-customer data)
- Password/PIN hashing
- Environment-based secret configuration
- SQLite locally; PostgreSQL can be supplied through `DATABASE_URL`
- Production WSGI entry point via Gunicorn

## 1. Run locally on Windows

Open PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:SECRET_KEY="replace-with-a-long-random-secret"
$env:STAFF_PIN="123456"
$env:SEED_DEMO="true"
python app.py
```

Open:

`http://127.0.0.1:5000`

### Demo customer

- Account: `100234`
- PIN: `4471`

### Staff

Use the `STAFF_PIN` value you set in the environment.

## 2. Run locally on macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
export SECRET_KEY="replace-with-a-long-random-secret"
export STAFF_PIN="123456"
export SEED_DEMO="true"
python app.py
```

## 3. Deploy to Render

1. Put the project in a GitHub repository. The repository root should contain `app.py`, `requirements.txt`, `Procfile`, `templates/`, and `static/`.
2. In Render, create a **Web Service** from the GitHub repository.
3. Build command:

```text
pip install -r requirements.txt
```

4. Start command:

```text
gunicorn app:app
```

5. Add these environment variables in Render:
   - `SECRET_KEY` = a long random secret
   - `STAFF_PIN` = a private staff PIN
   - `SEED_DEMO` = `true` for the portfolio demo
   - `FLASK_DEBUG` = `false`
6. Deploy.
7. Open the generated Render URL and test the demo customer login.

### Database note

By default the app uses SQLite. On hosting platforms, a local SQLite file can be ephemeral unless persistent storage is configured. For a durable deployed demo, provide a PostgreSQL connection string as:

```text
DATABASE_URL=postgresql://...
```

The application automatically accepts a standard `postgresql://` URL and also converts legacy `postgres://` URLs.

## 4. Before publishing

- Never commit `.env`, `bank.db`, passwords or secret keys.
- Change the demo staff PIN before sharing the deployed URL.
- Keep `FLASK_DEBUG=false`.
- Use HTTPS (Render provides HTTPS).
- Treat the project as a demo only; it has not been designed or audited for real banking/security/compliance requirements.

## Project structure

```text
bbk_bank_project/
├── app.py
├── requirements.txt
├── Procfile
├── runtime.txt
├── .env.example
├── .gitignore
├── README.md
├── templates/
│   └── index.html
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── app.js
```
