# CyberGuard Deployment

## Runtime configuration

Install dependencies with `python -m pip install -r requirements.txt` and set secrets in the process environment or a managed secret store. Never place real secrets in source control, HTML, JavaScript, or client-visible API responses.

Required settings:

- `AES_256_GCM_KEY`: URL-safe Base64 encoding of 32 cryptographically random bytes.
- `CLIENT_CAPABILITY_CODE`: high-entropy capability required by existing credential store/retrieve operations.
- `DATABASE_URL`: SQLAlchemy URL for a persistent database; SQLite is suitable only for a single-process local deployment.

Optional settings:

- `AES_256_GCM_PREVIOUS_KEYS`: comma-separated URL-safe Base64 keys used only to decrypt during rotation.
- `LEGACY_AES_KEY`: original 32-byte legacy key only while migrating old CFB-encrypted records.
- `COOKIE_SECURE`: defaults to `true`; set `false` only for local HTTP development.
- `SECURE_REQUESTS_PER_MINUTE`: capability-authorized request ceiling per source IP (default 180).
- `ADMIN_LOGIN_ATTEMPTS_PER_15_MINUTES`: failed administrator logins per source IP (default 10).
- `ADMIN_ACCOUNT_LOCKOUT_THRESHOLD` and `ADMIN_LOCKOUT_MINUTES`: account lockout policy (defaults 5 failures and 15 minutes).

Generate an encryption key without printing it into application logs:

```sh
openssl rand -base64 32 | tr '/+' '_-' | tr -d '='
```

Set the resulting value as `AES_256_GCM_KEY` through your deployment secret manager. Do not use the development preview key or store the value in a checked-in `.env` file.

## First administrator

With the production database and encryption key configured, run:

```sh
python main.py --username your-admin-name
```

Enter a unique password of at least 14 characters at the hidden prompts. Add the one-time TOTP seed printed by the local command to an authenticator app immediately. The seed is encrypted in the database and is not available through the API. If it is lost, provision a replacement through a controlled server-side recovery procedure; the dashboard cannot reveal it.

## Start the service

```sh
uvicorn main:app --host 127.0.0.1 --port 8000
```

Place it behind a TLS-terminating reverse proxy, set `COOKIE_SECURE=true`, restrict access to the database and backups, and set the trusted proxy/network configuration at the deployment layer. `/healthz` reports database and encryption readiness.

## Encryption key rotation

1. Create a new independent 32-byte key and configure it as `AES_256_GCM_KEY`.
2. Temporarily configure the old key in `AES_256_GCM_PREVIOUS_KEYS`.
3. Restart the service and sign in as an administrator. Open Cloud Security Center and run **Rotate encryption**. The server rewraps credential records and administrator MFA seeds under the current key and reports only record counts.
4. Confirm rotation completed, then remove the old key and restart. Keep a protected backup until the data has been verified.

Never remove an old key while records encrypted under it may still exist. Legacy CFB data requires `LEGACY_AES_KEY` to remain configured until it has been migrated.

## Deployment boundaries

Administrator accounts use Argon2id passwords, TOTP, HttpOnly/SameSite session cookies, CSRF checks, and server-side expiring sessions. The existing ordinary data operations still use the legacy shared client capability; they are not individual user accounts. Rate-limit state is process-local, so multi-worker or multi-instance deployments should move it to a shared store. Cloud provider posture checks, external SIEM integration, and payment/subscription processing are not implemented; the interface reports provider integration as not connected. No payment behavior is simulated.