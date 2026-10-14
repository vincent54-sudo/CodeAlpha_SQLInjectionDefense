# CyberGuard Security Platform

CyberGuard is a Python and FastAPI application that demonstrates secure data handling, SQL-injection detection, encrypted credential storage, per-session isolation, and an administrator dashboard. The public interface creates a private client session automatically, and the admin dashboard uses Google authentication with a configured email allowlist.

## Features

- Automatic per-visitor client sessions with private data isolation
- AES-256-GCM encryption for protected records
- SQL injection signature detection and blocked request logging
- Admin dashboard with authentication, audit log export, incident tracking, and key rotation
- Google OAuth/OpenID Connect support for authorized administrators
- PostgreSQL-ready deployment with Render-compatible environment variables

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-test.txt
```

Set the required environment variables before starting the application:

```bash
export AES_256_GCM_KEY="..."
export DATABASE_URL="sqlite:///secure_cloud.db"
export GOOGLE_CLIENT_ID="..."
export GOOGLE_CLIENT_SECRET="..."
export GOOGLE_REDIRECT_URI="http://127.0.0.1:8000/auth/google/callback"
export ADMIN_ALLOWED_GOOGLE_EMAILS="admin@example.com"
```

Then start the service:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

## Testing

```bash
.venv/bin/python -m pytest -q
```

## Render deployment

Use the Render service command:

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Add the PostgreSQL connection and Google OAuth environment values in your Render dashboard. The app exposes `/healthz` for service health checks and continues to retain a legacy compatibility fallback for older clients.

## Security notes

- Secrets must live in the deployment environment, not in the repository.
- Email allowlists control which Google accounts may access the admin dashboard.
- Cookies are HttpOnly and SameSite protected.
- The app attempts to keep request and credential data redacted in audit logs.
