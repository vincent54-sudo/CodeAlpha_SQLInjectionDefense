# CyberGuard Deployment

## Runtime configuration

Install dependencies with `python -m pip install -r requirements.txt` and keep secrets in your hosting platform secret manager instead of source control. The application expects a persistent database, TLS termination in front of the service, and secure cookies for both the visitor session and the administrator session.

Required settings:

- `AES_256_GCM_KEY`: URL-safe Base64 encoding of 32 random bytes for the active key.
- `DATABASE_URL`: SQLAlchemy URL for the operational database. Render should use its PostgreSQL connection string.
- `GOOGLE_CLIENT_ID`: Google OAuth client ID for the admin sign-in flow.
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret for the admin sign-in flow.
- `GOOGLE_REDIRECT_URI`: full callback URL, for example `https://your-app.onrender.com/auth/google/callback`.
- `ADMIN_ALLOWED_GOOGLE_EMAILS`: comma-separated allowlist of authorized administrator emails.

Recommended and optional settings:

- `AES_256_GCM_PREVIOUS_KEYS`: comma-separated old keys still used during rotation.
- `LEGACY_AES_KEY`: legacy 32-byte CFB key only while migrating old records.
- `COOKIE_SECURE`: defaults to `true`; set to `false` only for local HTTP development.
- `CLIENT_CAPABILITY_CODE`: legacy fallback for existing clients; the app now creates a private client session automatically and does not require it for normal public use.
- `SECURE_REQUESTS_PER_MINUTE`: per-IP request ceiling for protected routes and legacy authorization checks.
- `ADMIN_LOGIN_ATTEMPTS_PER_15_MINUTES`: failed administrator logins per source IP.
- `ADMIN_ACCOUNT_LOCKOUT_THRESHOLD` and `ADMIN_LOCKOUT_MINUTES`: account lockout thresholds.

Generate an encryption key without printing it into logs:

```sh
openssl rand -base64 32 | tr '/+' '_-' | tr -d '='
```

Use the result as `AES_256_GCM_KEY` in the deployment secret manager. Do not store a real key in a checked-in `.env` file or in client-side code.

## Render deployment

Use the Render web service command:

```sh
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Set the following in the Render environment settings:

- `DATABASE_URL` -> your PostgreSQL connection string
- `AES_256_GCM_KEY` -> your active 32-byte key
- `GOOGLE_CLIENT_ID` -> Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` -> Google OAuth client secret
- `GOOGLE_REDIRECT_URI` -> the public callback URL
- `ADMIN_ALLOWED_GOOGLE_EMAILS` -> allowed admin email list
- `COOKIE_SECURE` -> `true` for HTTPS deployments

If you simultaneously support a legacy client or an older UI, leave `CLIENT_CAPABILITY_CODE` present as a compatibility fallback, but the default sessioned flow does not depend on it.

## Admin sign-in setup

1. Create a Google OAuth client at Google Cloud Console.
2. Add the redirect URI exactly matching `/auth/google/callback`.
3. Set `ADMIN_ALLOWED_GOOGLE_EMAILS` to the emails that may access the dashboard.
4. Restart the service and open the app.
5. Select the Google sign-in flow from the administrator section.

The server validates the Google ID token, checks the issuer and audience, confirms the email is verified, and then opens a session. The dashboard still supports the older TOTP-admin path for compatibility, but Google auth is the intended path.

## Session isolation and data safety

The public store and retrieve flow creates and reuses a private client session cookie for every browser. User records are tied to that session with a `session_id`, so one visitor cannot access another visitor's protected credentials. The backend still blocks malicious SQL input and records suspicious activity before any query runs.

## Encryption key rotation

1. Create a new 32-byte key and set it as `AES_256_GCM_KEY`.
2. Place the old key into `AES_256_GCM_PREVIOUS_KEYS` temporarily.
3. Sign in as an administrator and trigger the rotation action in the dashboard.
4. Verify the protected records were rewrapped and then remove the old key from the environment.

Never remove a previous key while records encrypted under it may still exist. Legacy CFB records still require `LEGACY_AES_KEY` until the migration is complete.

## Start the service locally

```sh
uvicorn main:app --host 127.0.0.1 --port 8000
```

The `/healthz` endpoint reports database, encryption, and service readiness. Use a reverse proxy with TLS in production and keep all secrets in the host platform rather than in the repository.