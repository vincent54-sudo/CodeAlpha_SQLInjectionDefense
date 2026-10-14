from starlette.middleware.sessions import SessionMiddleware
import base64
import argparse
import csv
import getpass
import hashlib
import hmac
import html
import io
import json
import os
from dotenv import load_dotenv
load_dotenv()
import re
import secrets
import struct
import threading
import unicodedata
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Generator
from urllib.parse import quote, unquote, urlencode
from urllib.request import urlopen

import requests
from argon2 import PasswordHasher
from authlib.jose import jwt

from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine, func, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(APP_DIR, 'secure_cloud.db')}")
CLIENT_CAPABILITY_CODE = os.getenv("CLIENT_CAPABILITY_CODE", "")
GCM_KEY_ENV = "AES_256_GCM_KEY"
LEGACY_KEY_ENV = "LEGACY_AES_KEY"
GCM_AAD = b"secure-cloud-credential:v2"
CLIENT_SESSION_COOKIE = "cyberguard_client_session"
CLIENT_SESSION_TTL = timedelta(days=7)
ADMIN_SESSION_COOKIE = "cyberguard_admin_session"
ADMIN_SESSION_TTL = timedelta(hours=8)
password_hasher = PasswordHasher()

app = FastAPI(title="CodeAlpha Secure Data & SQL Injection Defense")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "local-development-secret-change-me"),
    same_site="lax",
    https_only=False
)
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(request: Request, exc: RequestValidationError):
    errors = [
        {"loc": error.get("loc", ()), "msg": error.get("msg", "Invalid value"), "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors}, headers={"Cache-Control": "no-store"})

engine_options = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class ClientSession(Base):
    __tablename__ = "client_sessions"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc) + timedelta(days=7))
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    user_agent = Column(String(255), default="")


class UserRecord(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("client_sessions.id", ondelete="CASCADE"), nullable=True, index=True)
    username = Column(String(128), index=True, nullable=False)
    encrypted_credential = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class GoogleOAuthState(Base):
    __tablename__ = "google_oauth_state"

    id = Column(Integer, primary_key=True, index=True)
    state = Column(String(128), unique=True, index=True, nullable=False)
    nonce = Column(String(128), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class SecurityAuditLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    attempted_input = Column(String(255), index=True)
    status = Column(String(40), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    event_type = Column(String(40), nullable=False, default="legacy")
    severity = Column(String(16), nullable=False, default="info")
    source_ip = Column(String(64), index=True)
    pattern = Column(String(255))
    incident_notes = Column(Text, nullable=False, default="")
    resolved = Column(Boolean, nullable=False, default=False)


class AdminAccount(Base):
    __tablename__ = "admin_accounts"

    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    mfa_secret_encrypted = Column(Text, nullable=False)
    role = Column(String(32), nullable=False, default="admin")
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    admin_id = Column(Integer, ForeignKey("admin_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


def migrate_schema() -> None:
    """Add audit metadata without replacing or rebuilding existing tables."""
    Base.metadata.create_all(bind=engine)
    columns = {column["name"] for column in inspect(engine).get_columns("security_logs")}
    additions = {
        "event_type": "VARCHAR(40) NOT NULL DEFAULT 'legacy'",
        "severity": "VARCHAR(16) NOT NULL DEFAULT 'info'",
        "source_ip": "VARCHAR(64)",
        "pattern": "VARCHAR(255)",
        "incident_notes": "TEXT NOT NULL DEFAULT ''",
        "resolved": "BOOLEAN NOT NULL DEFAULT FALSE",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE security_logs ADD COLUMN {name} {definition}"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_security_logs_event_type ON security_logs (event_type)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_security_logs_timestamp ON security_logs (timestamp)"))

    inspector = inspect(engine)
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table_name, required_columns in {
            "users": [
                ("session_id", "INTEGER"),
                ("created_at", "TIMESTAMP"),
                ("username", "VARCHAR(128)"),
                ("encrypted_credential", "TEXT"),
            ],
            "client_sessions": [
                ("token_hash", "VARCHAR(64)"),
                ("created_at", "TIMESTAMP"),
                ("expires_at", "TIMESTAMP"),
                ("last_seen_at", "TIMESTAMP"),
                ("user_agent", "VARCHAR(255)"),
            ],
            "google_oauth_state": [
                ("state", "VARCHAR(128)"),
                ("nonce", "VARCHAR(128)"),
                ("expires_at", "TIMESTAMP"),
                ("created_at", "TIMESTAMP"),
            ],
        }.items():
            if not inspector.has_table(table_name):
                continue
            existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, column_type in required_columns:
                if column_name not in existing_columns:
                    connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


    # Make obsolete legacy columns optional on PostgreSQL.
    # Current UserRecord fields remain unchanged.
    if engine.dialect.name == "postgresql":
        model_columns = set(UserRecord.__table__.columns.keys())
        legacy_columns = [
            column["name"]
            for column in inspect(engine).get_columns("users")
            if column["name"] not in model_columns
            and column["name"] != "id"
            and not column["nullable"]
        ]

        if legacy_columns:
            with engine.begin() as connection:
                for column_name in legacy_columns:
                    quoted_name = connection.dialect.identifier_preparer.quote(column_name)
                    connection.execute(
                        text(f"ALTER TABLE users ALTER COLUMN {quoted_name} DROP NOT NULL")
                    )


migrate_schema()


def _resolve_or_create_runtime_key(environment_name: str) -> str:
    encoded = os.getenv(environment_name, "")
    if encoded:
        return encoded
    generated = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    os.environ[environment_name] = generated
    return generated


def _decode_key(environment_name: str) -> bytes:
    encoded = _resolve_or_create_runtime_key(environment_name)
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError(f"{environment_name} must be URL-safe base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"{environment_name} must decode to exactly 32 bytes")
    return key


def _available_encryption_keys() -> list[bytes]:
    current = _decode_key(GCM_KEY_ENV)
    previous = [value.strip() for value in os.getenv("AES_256_GCM_PREVIOUS_KEYS", "").split(",") if value.strip()]
    return [current, *(_decode_encoded_key(value) for value in previous)]


def _decode_encoded_key(encoded: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("A previous encryption key is not URL-safe base64") from exc
    if len(key) != 32:
        raise RuntimeError("A previous encryption key must decode to exactly 32 bytes")
    return key


def encrypt_data(plain_text: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_decode_key(GCM_KEY_ENV)).encrypt(nonce, plain_text.encode("utf-8"), GCM_AAD)
    return "v2:" + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")


def decrypt_data(encoded_text: str) -> str:
    if encoded_text.startswith("v2:"):
        encoded = encoded_text[3:]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(raw) < 12 + 16:
            raise ValueError("Invalid encrypted record")
        for key in _available_encryption_keys():
            try:
                return AESGCM(key).decrypt(raw[:12], raw[12:], GCM_AAD).decode("utf-8")
            except InvalidTag:
                continue
        raise InvalidTag

    legacy_key = os.getenv(LEGACY_KEY_ENV, "").encode("utf-8")
    if len(legacy_key) != 32:
        raise RuntimeError(f"{LEGACY_KEY_ENV} must be set to the original 32-byte key to migrate legacy records")
    raw = base64.b64decode(encoded_text, validate=True)
    if len(raw) <= 16:
        raise ValueError("Invalid legacy encrypted record")
    decryptor = Cipher(algorithms.AES(legacy_key), modes.CFB(raw[:16])).decryptor()
    return (decryptor.update(raw[16:]) + decryptor.finalize()).decode("utf-8")


def _uses_current_encryption_key(encoded_text: str) -> bool:
    if not encoded_text.startswith("v2:"):
        return False
    encoded = encoded_text[3:]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if len(raw) < 28:
        return False
    try:
        AESGCM(_decode_key(GCM_KEY_ENV)).decrypt(raw[:12], raw[12:], GCM_AAD)
        return True
    except InvalidTag:
        return False


SQLI_SIGNATURES = (
    ("UNION-based injection", re.compile(r"\bunion\b.{0,80}\bselect\b", re.I | re.S)),
    ("authentication-bypass tautology", re.compile(r"\b(?:or|and)\s+(?:(?:['\"][^'\"]*['\"]?|\d+)\s*=\s*(?:['\"][^'\"]*['\"]?|\d+)|true\s*=\s*true)", re.I)),
    ("stacked SQL statement", re.compile(r";\s*(?:select|insert|update|delete|drop|alter|create|truncate)\b", re.I)),
    ("database manipulation statement", re.compile(r"\b(?:drop|truncate)\s+(?:table|database|schema)\b|\b(?:alter|create)\s+(?:table|database|user|schema)\b|\bpragma\s+\w+", re.I)),
    ("SQL comment terminator", re.compile(r"(?:--|#|/\*|\*/)", re.I)),
)
SQL_TOKENS = re.compile(r"[a-z_]+|\d+|--|/\*|\*/|[#;=]", re.I)


def detect_sql_injection(value: str) -> list[str]:
    """Canonicalize input, then combine SQL token sequences and attack signatures."""
    canonical = unicodedata.normalize("NFKC", html.unescape(value))
    for _ in range(2):
        canonical = unquote(canonical)
    canonical = canonical.replace("+", " ")
    tokens = SQL_TOKENS.findall(canonical.lower())
    token_pairs = set(zip(tokens, tokens[1:]))
    findings = [name for name, signature in SQLI_SIGNATURES if signature.search(canonical)]
    if ("union", "select") in token_pairs and "UNION-based injection" not in findings:
        findings.append("UNION-based injection")
    if any(marker in token_pairs for marker in (("--", ""), ("/", "*"))) and "SQL comment terminator" not in findings:
        findings.append("SQL comment terminator")
    return findings


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    sensitive_credential: str = Field(min_length=1, max_length=4096)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("Username cannot contain control characters")
        normalized = value.strip()
        if not normalized:
            raise ValueError("Username cannot be empty")
        return normalized


class UserSearch(BaseModel):
    username: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("Username cannot contain control characters")
        normalized = value.strip()
        if not normalized:
            raise ValueError("Username cannot be empty")
        return normalized


class AdminLogin(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    totp_code: str = Field(min_length=6, max_length=6)


class IncidentUpdate(BaseModel):
    notes: str = Field(default="", max_length=4000)
    resolved: bool


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _normalise_email_list(raw_value: str) -> set[str]:
    return {email.strip().lower() for email in raw_value.split(",") if email.strip()}


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _policy_int(name: str, default: int, minimum: int = 1, maximum: int = 100_000) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def record_event(
    db: Session,
    *,
    request: Request,
    event_type: str,
    status: str,
    label: str,
    severity: str = "info",
    pattern: str | None = None,
) -> SecurityAuditLog:
    source_ip = _client_ip(request)
    recent_count = db.query(func.count(SecurityAuditLog.id)).filter(
        SecurityAuditLog.source_ip == source_ip,
        SecurityAuditLog.event_type == event_type,
        SecurityAuditLog.timestamp >= datetime.now(timezone.utc) - timedelta(minutes=15),
    ).scalar() or 0
    escalation_events = {"sql_injection", "unauthorized_access", "suspicious_login", "rate_limit", "data_access_alert"}
    if event_type in escalation_events:
        severity = "critical" if recent_count >= 4 else "high" if severity == "info" else severity
    event = SecurityAuditLog(
        attempted_input=label[:255],
        status=status,
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        pattern=pattern[:255] if pattern else None,
    )
    db.add(event)
    db.commit()
    return event


failed_capability_attempts: dict[str, deque[datetime]] = defaultdict(deque)
capability_request_windows: dict[str, deque[datetime]] = defaultdict(deque)
failed_admin_logins: dict[str, deque[datetime]] = defaultdict(deque)
attempt_lock = threading.Lock()


def _authorize(request: Request, supplied: str | None, expected: str, permission: str) -> str:
    if not expected:
        raise HTTPException(status_code=503, detail=f"{permission} capability is not configured on the server")
    source_ip = _client_ip(request)
    now = datetime.now(timezone.utc)
    with attempt_lock:
        request_window = capability_request_windows[source_ip]
        while request_window and request_window[0] < now - timedelta(minutes=1):
            request_window.popleft()
        if len(request_window) >= _policy_int("SECURE_REQUESTS_PER_MINUTE", 180):
            with SessionLocal() as db:
                record_event(db, request=request, event_type="rate_limit", status="Blocked", label="capability request rate limit", severity="high")
            raise HTTPException(status_code=429, detail="Request rate exceeded. Try again shortly.")
        request_window.append(now)
        attempts = failed_capability_attempts[source_ip]
        while attempts and attempts[0] < now - timedelta(minutes=5):
            attempts.popleft()
        if len(attempts) >= 12:
            with SessionLocal() as db:
                record_event(db, request=request, event_type="rate_limit", status="Blocked", label="capability rate limit", severity="high")
            raise HTTPException(status_code=429, detail="Too many authorization attempts. Try again later.")

    if supplied is None or not secrets.compare_digest(supplied, expected):
        with attempt_lock:
            failed_capability_attempts[source_ip].append(now)
        with SessionLocal() as db:
            record_event(db, request=request, event_type="unauthorized_access", status="Denied", label=f"{permission} authorization failed", severity="high")
        raise HTTPException(status_code=403, detail="Access denied")

    with SessionLocal() as db:
        record_event(db, request=request, event_type="authorization_succeeded", status="Success", label=f"{permission} authorization")
    return permission


def verify_client_capability(
    request: Request,
    x_capability_code: str | None = Header(default=None),
) -> str:
    return _authorize(request, x_capability_code, CLIENT_CAPABILITY_CODE, "client")


def _ensure_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _csrf_token(session_token: str) -> str:
    return hmac.new(session_token.encode("ascii"), b"cyberguard-admin-csrf-v1", hashlib.sha256).hexdigest()


def _totp_code(secret: str, timestamp: int | None = None) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int((timestamp if timestamp is not None else int(datetime.now(timezone.utc).timestamp())) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def _verify_totp(secret: str, supplied_code: str) -> bool:
    if not re.fullmatch(r"\d{6}", supplied_code):
        return False
    now = int(datetime.now(timezone.utc).timestamp())
    return any(secrets.compare_digest(_totp_code(secret, now + offset * 30), supplied_code) for offset in (-1, 0, 1))


def _set_secure_cookie(response: Response, key: str, value: str, *, max_age: int, path: str = "/") -> None:
    response.set_cookie(
        key,
        value,
        max_age=max_age,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() in {"1", "true", "yes"},
        samesite="lax",
        path=path,
    )


def get_or_create_client_session(request: Request, response: Response, db: Session) -> ClientSession:
    token = request.cookies.get(CLIENT_SESSION_COOKIE)
    now = datetime.now(timezone.utc)
    if token:
        session = db.query(ClientSession).filter_by(token_hash=_token_hash(token)).first()
        if session:
            expires_at = _ensure_utc(session.expires_at)
            if expires_at > now:
                session.last_seen_at = now
                if expires_at - now < timedelta(days=2):
                    session.expires_at = now + CLIENT_SESSION_TTL
                db.commit()
                request.state.client_session_token = token
                return session
            db.delete(session)
            db.commit()
    token = secrets.token_urlsafe(32)
    session = ClientSession(
        token_hash=_token_hash(token),
        created_at=now,
        expires_at=now + CLIENT_SESSION_TTL,
        last_seen_at=now,
        user_agent=request.headers.get("user-agent", "")[:255],
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    _set_secure_cookie(response, CLIENT_SESSION_COOKIE, token, max_age=int(CLIENT_SESSION_TTL.total_seconds()))
    request.state.client_session_token = token
    return session


def require_client_session(request: Request, response: Response, db: Session = Depends(get_db)) -> ClientSession:
    session = get_or_create_client_session(request, response, db)
    request.state.client_session_id = session.id
    request.state.client_csrf = _csrf_token(getattr(request.state, "client_session_token", request.cookies.get(CLIENT_SESSION_COOKIE) or ""))
    return session


def require_client_csrf(
    request: Request,
    session: ClientSession = Depends(require_client_session),
    x_csrf_token: str | None = Header(default=None),
) -> ClientSession:
    expected = getattr(request.state, "client_csrf", "")
    if x_csrf_token and expected and not secrets.compare_digest(x_csrf_token, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    return session


def require_admin(request: Request) -> AdminAccount:
    token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Administrator authentication required")
    with SessionLocal() as db:
        session = db.query(AdminSession).filter_by(token_hash=_token_hash(token)).first()
        now = datetime.now(timezone.utc)
        expires_at = session.expires_at.replace(tzinfo=timezone.utc) if session and session.expires_at.tzinfo is None else (session.expires_at if session else now)
        if not session or expires_at <= now:
            if session:
                db.delete(session)
                db.commit()
            raise HTTPException(status_code=401, detail="Administrator session expired")
        admin = db.query(AdminAccount).filter_by(id=session.admin_id, is_active=True).first()
        if not admin or admin.role != "admin":
            raise HTTPException(status_code=403, detail="Administrator permission required")
        session.last_seen_at = now
        db.commit()
        db.refresh(admin)
        db.expunge(admin)
        request.state.admin_session_hash = session.token_hash
        request.state.admin_csrf = _csrf_token(token)
        request.state.admin_id = admin.id
        return admin


def require_admin_csrf(
    request: Request,
    admin: AdminAccount = Depends(require_admin),
    x_csrf_token: str | None = Header(default=None),
) -> AdminAccount:
    expected = getattr(request.state, "admin_csrf", "")
    if not x_csrf_token or not secrets.compare_digest(x_csrf_token, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    return admin


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.path.startswith("/") and not request.url.path.startswith("/auth/") and not request.url.path.startswith("/secure") and not request.url.path.startswith("/static"):
        try:
            with SessionLocal() as db:
                get_or_create_client_session(request, response, db)
        except Exception:
            pass
    if request.url.path.startswith("/secure/"):
        response.headers["Cache-Control"] = "no-store"
        route = request.scope.get("route")
        route_path = getattr(route, "path", "/secure/")
        try:
            with SessionLocal() as db:
                record_event(
                    db,
                    request=request,
                    event_type="request_monitored",
                    status=f"HTTP {response.status_code}",
                    label=f"{request.method} {route_path}",
                    severity="medium" if response.status_code >= 400 else "info",
                )
        except Exception:
            pass
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(os.path.join(APP_DIR, "static", "index.html"))


@app.get("/healthz", include_in_schema=False)
def health_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        return {"status": "degraded", "version": "1.0.0", "database": "unavailable"}
    try:
        _available_encryption_keys()
        encryption = "configured"
    except RuntimeError:
        encryption = "configuration required"
    status = "ok" if encryption == "configured" else "degraded"
    return {"status": status, "version": "1.0.0", "database": "operational", "encryption": encryption}


@app.get("/secure/help", include_in_schema=False)
def get_help_guide():
    return {
        "title": "How this security search system works",
        "plain_language": "Think of this as a secure search and protection workflow. The app creates a private session for each visitor automatically, checks the username for unsafe SQL patterns, and only returns a result if the request is safe and the data belongs to the same session.",
        "steps": [
            {
                "title": "1. Open the app and start a session",
                "detail": "When you open the site, the server creates a private client session automatically. No manual code entry is required."
            },
            {
                "title": "2. Store protected data safely",
                "detail": "Type a username and a secret, and the app encrypts that value before storing it. It stays protected in the database."
            },
            {
                "title": "3. Retrieve only your own data",
                "detail": "The lookup is tied to your session, so your records stay private and other visitors cannot read them."
            },
            {
                "title": "4. Test safe and blocked searches",
                "detail": "A normal username works. A suspicious SQL payload is blocked, logged, and shown as a security alert instead of being executed."
            },
            {
                "title": "5. Admin access uses Google",
                "detail": "Authorized administrators sign in with Google. The app verifies the account, checks the allowlist, and then opens the security dashboard."
            }
        ],
        "common_tasks": [
            {"label": "Store a secret", "detail": "Enter a username and credential, then click Encrypt and store."},
            {"label": "Retrieve a record", "detail": "Search for your own username to view the encrypted value that belongs to your session."},
            {"label": "Test the filter", "detail": "Try a normal username and then a blocked SQL pattern to see the difference."},
            {"label": "Admin sign in", "detail": "Open the security operations section and click Continue with Google."}
        ],
        "examples": [
            {"label": "Safe example", "example": "alice"},
            {"label": "Blocked SQL probe", "example": "' OR '1'='1 --"},
            {"label": "Your protected data", "example": "Stored only inside your own session"}
        ]
    }


@app.get("/secure/client-session", include_in_schema=False)
def get_client_session(request: Request, response: Response, db: Session = Depends(get_db)):
    session = get_or_create_client_session(request, response, db)
    token = request.cookies.get(CLIENT_SESSION_COOKIE) or secrets.token_urlsafe(32)
    return {"status": "active", "session_id": session.id, "csrf_token": _csrf_token(token)}


@app.post("/secure/store")
def store_user_data(
    user: UserCreate,
    request: Request,
    response: Response,
    session: ClientSession = Depends(require_client_csrf),
    db: Session = Depends(get_db),
):
    if request.headers.get("x-capability-code") is not None:
        _authorize(request, request.headers.get("x-capability-code"), CLIENT_CAPABILITY_CODE, "client")
    if not getattr(request.state, "client_session_id", None):
        raise HTTPException(status_code=401, detail="Client session required")
    existing_user = db.query(UserRecord).filter(UserRecord.session_id == session.id, UserRecord.username == user.username).first()
    if existing_user:
        record_event(db, request=request, event_type="store_conflict", status="Rejected", label="duplicate username")
        raise HTTPException(status_code=409, detail="A record with that username already exists in this session.")
    try:
        encrypted_value = encrypt_data(user.sensitive_credential)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Encryption is not configured correctly on the server.") from exc
    db.add(UserRecord(session_id=session.id, username=user.username, encrypted_credential=encrypted_value))
    db.commit()
    record_event(db, request=request, event_type="data_stored", status="Success", label="credential stored")
    return {"status": "Success", "message": "Credential encrypted and stored.", "encryption_algorithm": "AES-256-GCM"}


@app.post("/secure/retrieve")
def retrieve_user_data(
    search: UserSearch,
    request: Request,
    session: ClientSession = Depends(require_client_csrf),
    db: Session = Depends(get_db),
):
    if request.headers.get("x-capability-code") is not None:
        _authorize(request, request.headers.get("x-capability-code"), CLIENT_CAPABILITY_CODE, "client")
    findings = detect_sql_injection(search.username)
    if findings:
        record_event(
            db,
            request=request,
            event_type="sql_injection",
            status="Blocked",
            label="suspicious query input redacted",
            severity="high",
            pattern="; ".join(findings),
        )
        return {"status": "Blocked", "message": "The request matched suspicious SQL activity and was not executed.", "alerts": findings}

    user_record = db.query(UserRecord).filter(UserRecord.session_id == session.id, UserRecord.username == search.username).first()
    if not user_record:
        record_event(db, request=request, event_type="record_not_found", status="Not found", label="credential lookup")
        return {"status": "Not found", "message": "No record matched that username in this session."}

    try:
        decrypted_credential = decrypt_data(user_record.encrypted_credential)
        if not _uses_current_encryption_key(user_record.encrypted_credential):
            user_record.encrypted_credential = encrypt_data(decrypted_credential)
            db.commit()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Legacy record migration key is unavailable or encryption is not configured.") from exc
    except (InvalidTag, ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
        record_event(db, request=request, event_type="decryption_failure", status="Failed", label="credential decryption failed", severity="high")
        raise HTTPException(status_code=500, detail="The stored credential could not be safely decrypted.") from exc

    record_event(db, request=request, event_type="data_retrieved", status="Success", label="credential retrieved")
    return {
        "status": "Success",
        "username": user_record.username,
        "decrypted_plain_text": decrypted_credential,
        "encryption_algorithm": "AES-256-GCM",
    }


def _get_google_oauth_client() -> OAuth:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "")
    if not client_id or not client_secret or not redirect_uri:
        raise HTTPException(status_code=503, detail="Google OAuth is not configured")
    oauth = OAuth()
    oauth.register(
        "google",
        client_id=client_id,
        client_secret=client_secret,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        access_token_url="https://oauth2.googleapis.com/token",
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth


def _verify_google_id_token(id_token: str) -> dict:
    import base64

    if not id_token:
        raise ValueError("Missing Google ID token")

    # Read the untrusted header only to select Google's signing key.
    try:
        encoded_header = id_token.split(".")[0]
        padded_header = encoded_header + "=" * (-len(encoded_header) % 4)
        unverified_header = json.loads(
            base64.urlsafe_b64decode(padded_header).decode("utf-8")
        )
    except Exception as error:
        raise ValueError("Invalid Google ID token header") from error

    if unverified_header.get("alg") != "RS256":
        raise ValueError("Unsupported Google ID token algorithm")

    kid = unverified_header.get("kid")
    if not kid:
        raise ValueError("Google signing key ID missing")

    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    with urlopen(jwks_url, timeout=10) as response:
        jwks = json.load(response)

    key_data = next(
        (key for key in jwks.get("keys", []) if key.get("kid") == kid),
        None,
    )
    if key_data is None:
        raise ValueError("Google signing key not found")

    # Authlib verifies the token signature using Google's public key.
    claims = jwt.decode(id_token, key_data)
    claims.validate()

    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    if not client_id:
        raise ValueError("Google client ID is not configured")

    if claims.get("iss") not in {
        "https://accounts.google.com",
        "accounts.google.com",
    }:
        raise ValueError("Invalid Google issuer")

    audience = claims.get("aud")
    if isinstance(audience, list):
        if client_id not in audience:
            raise ValueError("Invalid Google audience")
        if len(audience) > 1 and claims.get("azp") != client_id:
            raise ValueError("Invalid Google authorized party")
    elif audience != client_id:
        raise ValueError("Invalid Google audience")

    now = datetime.now(timezone.utc).timestamp()
    if claims.get("exp", 0) < now:
        raise ValueError("Expired Google ID token")

    if not claims.get("email_verified"):
        raise ValueError("Google email not verified")

    email = str(claims.get("email", "")).strip().lower()
    if not email:
        raise ValueError("Google email missing")

    return {
        "email": email,
        "name": claims.get("name", email),
        "picture": claims.get("picture"),
    }


@app.get("/auth/google/login")
async def google_login(request: Request, response: Response, db: Session = Depends(get_db)):
    oauth = _get_google_oauth_client()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.add(GoogleOAuthState(state=state, nonce=nonce, expires_at=expires_at))
    db.commit()
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "")
    return await oauth.google.authorize_redirect(request, redirect_uri, state=state, nonce=nonce)


@app.get("/auth/google/callback")
async def google_callback(request: Request, response: Response, db: Session = Depends(get_db)):
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    if not state or not code:
        raise HTTPException(status_code=400, detail="Google callback missing required parameters")
    oauth_state = db.query(GoogleOAuthState).filter_by(state=state).first()
    if not oauth_state or (
        oauth_state.expires_at.replace(tzinfo=timezone.utc)
        if oauth_state.expires_at.tzinfo is None
        else oauth_state.expires_at
    ) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Google authentication state expired or invalid")
    oauth = _get_google_oauth_client()
    try:
        token = await oauth.google.authorize_access_token(request)
        id_token = token.get("id_token")
        claims = _verify_google_id_token(id_token)
    except Exception as error:
        import traceback
        print("GOOGLE OAUTH CALLBACK FAILURE:", flush=True)
        traceback.print_exc()
        raise HTTPException(
            status_code=401,
            detail=f"Google authentication failed: {type(error).__name__}"
        ) from error

    email = claims["email"].lower()
    allowed_emails = _normalise_email_list(os.getenv("ADMIN_ALLOWED_GOOGLE_EMAILS", ""))
    if email not in allowed_emails:
        return JSONResponse(status_code=403, content={"detail": "Access denied: Google account is not an authorized administrator."})

    admin = db.query(AdminAccount).filter_by(username=email).first()
    if not admin:
        admin = AdminAccount(
            username=email,
            password_hash=password_hasher.hash(secrets.token_urlsafe(32)),
            mfa_secret_encrypted=encrypt_data(base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)

    token_value = secrets.token_urlsafe(32)
    db.add(AdminSession(admin_id=admin.id, token_hash=_token_hash(token_value), expires_at=datetime.now(timezone.utc) + ADMIN_SESSION_TTL))
    db.commit()
    response.set_cookie(
        ADMIN_SESSION_COOKIE,
        token_value,
        max_age=int(ADMIN_SESSION_TTL.total_seconds()),
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() in {"1", "true", "yes"},
        samesite="lax",
        path="/",
    )
    db.delete(oauth_state)
    db.commit()
    return response


@app.post("/secure/admin/login")
def admin_login(credentials: AdminLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    source_ip = _client_ip(request)
    now = datetime.now(timezone.utc)
    with attempt_lock:
        attempts = failed_admin_logins[source_ip]
        while attempts and attempts[0] < now - timedelta(minutes=15):
            attempts.popleft()
        if len(attempts) >= _policy_int("ADMIN_LOGIN_ATTEMPTS_PER_15_MINUTES", 10):
            record_event(db, request=request, event_type="rate_limit", status="Blocked", label="administrator login rate limit", severity="high")
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    admin = db.query(AdminAccount).filter_by(username=credentials.username).first()
    is_locked = bool(admin and admin.locked_until and admin.locked_until.replace(tzinfo=timezone.utc) > now)
    valid = False
    if admin and admin.is_active and not is_locked:
        try:
            valid = password_hasher.verify(admin.password_hash, credentials.password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid = False
        if valid:
            try:
                mfa_secret = decrypt_data(admin.mfa_secret_encrypted)
                valid = _verify_totp(mfa_secret, credentials.totp_code)
                if valid and not _uses_current_encryption_key(admin.mfa_secret_encrypted):
                    admin.mfa_secret_encrypted = encrypt_data(mfa_secret)
            except (RuntimeError, InvalidTag, ValueError, base64.binascii.Error):
                valid = False

    if not valid:
        with attempt_lock:
            failed_admin_logins[source_ip].append(now)
        if admin:
            admin.failed_login_count += 1
            if admin.failed_login_count >= _policy_int("ADMIN_ACCOUNT_LOCKOUT_THRESHOLD", 5, maximum=50):
                admin.locked_until = now + timedelta(minutes=_policy_int("ADMIN_LOCKOUT_MINUTES", 15, maximum=1440))
            db.commit()
        record_event(db, request=request, event_type="suspicious_login", status="Denied", label="administrator login failed", severity="high")
        raise HTTPException(status_code=401, detail="Invalid credentials or verification code")

    admin.failed_login_count = 0
    admin.locked_until = None
    if password_hasher.check_needs_rehash(admin.password_hash):
        admin.password_hash = password_hasher.hash(credentials.password)
    token = secrets.token_urlsafe(32)
    db.add(AdminSession(admin_id=admin.id, token_hash=_token_hash(token), expires_at=now + ADMIN_SESSION_TTL))
    db.commit()
    record_event(db, request=request, event_type="admin_login", status="Success", label="administrator authenticated")
    response.set_cookie(
        ADMIN_SESSION_COOKIE,
        token,
        max_age=int(ADMIN_SESSION_TTL.total_seconds()),
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() in {"1", "true", "yes"},
        samesite="strict",
        path="/",
    )
    return {"username": admin.username, "role": admin.role, "csrf_token": _csrf_token(token)}


@app.get("/secure/admin/session")
def get_admin_session(request: Request, admin: AdminAccount = Depends(require_admin)):
    token = request.cookies[ADMIN_SESSION_COOKIE]
    return {"username": admin.username, "role": admin.role, "csrf_token": _csrf_token(token)}


@app.post("/secure/admin/logout")
def admin_logout(
    request: Request,
    response: Response,
    admin: AdminAccount = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
):
    db.query(AdminSession).filter_by(token_hash=request.state.admin_session_hash).delete()
    db.commit()
    response.delete_cookie(ADMIN_SESSION_COOKIE, path="/", httponly=True, samesite="strict")
    record_event(db, request=request, event_type="admin_logout", status="Success", label="administrator signed out")
    return {"status": "Signed out"}


def _risk_details(event: SecurityAuditLog) -> tuple[int, str, str]:
    scores = {"info": 8, "low": 18, "medium": 42, "high": 72, "critical": 96}
    score = scores.get((event.severity or "info").lower(), 8)
    if event.event_type == "sql_injection":
        score = max(score, 86)
    elif event.event_type in {"suspicious_login", "unauthorized_access", "rate_limit"}:
        score = max(score, 68)
    elif event.status in {"Blocked", "Denied", "Failed"}:
        score = max(score, 52)
    level = "CRITICAL" if score >= 90 else "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW"
    reasons = {
        "sql_injection": "Input matched a SQL injection signature and was not executed.",
        "suspicious_login": "Administrator credentials or MFA verification failed.",
        "unauthorized_access": "A protected endpoint received invalid authorization.",
        "rate_limit": "Request frequency exceeded the configured authorization limit.",
    }
    return score, level, reasons.get(event.event_type, f"Recorded application event: {event.event_type}.")


@app.get("/secure/admin/dashboard-data")
def get_admin_dashboard_data(admin: AdminAccount = Depends(require_admin), db: Session = Depends(get_db)):
    logs = db.query(SecurityAuditLog).filter(SecurityAuditLog.event_type != "request_monitored").order_by(SecurityAuditLog.id.desc()).limit(100).all()
    users = db.query(UserRecord.id, UserRecord.username).order_by(UserRecord.id.desc()).limit(100).all()
    count_event = lambda event_type: db.query(func.count(SecurityAuditLog.id)).filter(SecurityAuditLog.event_type == event_type).scalar() or 0
    blocked_count = db.query(func.count(SecurityAuditLog.id)).filter(
        SecurityAuditLog.event_type.in_(("sql_injection", "unauthorized_access", "rate_limit"))
    ).scalar() or 0
    suspicious_ips = db.query(SecurityAuditLog.source_ip, func.count(SecurityAuditLog.id).label("events")).filter(
        SecurityAuditLog.severity.in_(("high", "critical")), SecurityAuditLog.source_ip.isnot(None)
    ).group_by(SecurityAuditLog.source_ip).order_by(func.count(SecurityAuditLog.id).desc()).limit(10).all()
    alert_count = db.query(func.count(SecurityAuditLog.id)).filter(SecurityAuditLog.severity.in_(("high", "critical"))).scalar() or 0
    trend_start = datetime.now(timezone.utc) - timedelta(days=29)
    daily_counts = db.query(
        func.date(SecurityAuditLog.timestamp).label("event_day"),
        SecurityAuditLog.event_type,
        func.count(SecurityAuditLog.id),
    ).filter(SecurityAuditLog.timestamp >= trend_start).group_by(
        func.date(SecurityAuditLog.timestamp), SecurityAuditLog.event_type
    ).all()
    daily_activity: dict[str, dict[str, int | str]] = {}
    for event_day, event_type, count in daily_counts:
        day_key = str(event_day)
        bucket = daily_activity.setdefault(day_key, {"date": day_key, "threats": 0, "other": 0})
        category = "threats" if event_type == "sql_injection" else "other"
        bucket[category] += count
    try:
        _decode_key(GCM_KEY_ENV)
        encryption_status = "Operational"
    except RuntimeError:
        encryption_status = "Configuration required"
    admin_configured = db.query(AdminAccount).filter_by(is_active=True).count() > 0

    return {
        "status": "Authorized",
        "product": {"name": "CyberGuard Security Platform", "version": "1.0.0", "license": "community"},
        "total_requests_monitored": count_event("request_monitored"),
        "daily_activity": [daily_activity[key] for key in sorted(daily_activity)],
        "system_status": "Operational" if encryption_status == "Operational" and admin_configured else "Degraded",
        "encryption_status": encryption_status,
        "total_users": db.query(func.count(UserRecord.id)).scalar() or 0,
        "total_threat_logs": count_event("sql_injection"),
        "blocked_suspicious_requests": blocked_count,
        "successful_authentication_attempts": count_event("authorization_succeeded"),
        "failed_authentication_attempts": count_event("unauthorized_access") + count_event("suspicious_login"),
        "database_activity": {"stored": count_event("data_stored"), "retrieved": count_event("data_retrieved")},
        "alert_count": alert_count,
        "cloud_security": {
            "application_security": "Operational",
            "database_security": "Bound ORM queries",
            "encryption": encryption_status,
            "authentication": "Argon2id + TOTP" if admin_configured else "Administrator setup required",
            "api_security": "Security headers + rate-limited authorization",
            "cloud_provider": "Not integrated",
            "checks": [
                {"name": "Parameterized database access", "status": "Implemented"},
                {"name": "AES-256-GCM credential encryption", "status": encryption_status},
                {"name": "Administrator MFA", "status": "Implemented" if admin_configured else "Setup required"},
                {"name": "Cloud provider posture checks", "status": "Integration required"},
            ],
        },
        "suspicious_ips": [{"ip": ip, "events": count} for ip, count in suspicious_ips],
        "users": [{"id": user_id, "username": username} for user_id, username in users],
        "logs": [
            {
                "id": log.id,
                "status": log.status,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "event_type": log.event_type,
                "severity": log.severity,
                "source_ip": log.source_ip,
                "pattern": log.pattern,
                "risk_score": _risk_details(log)[0],
                "risk_level": _risk_details(log)[1],
                "reason": _risk_details(log)[2],
                "notes": log.incident_notes,
                "resolved": log.resolved,
            }
            for log in logs
        ],
    }


@app.patch("/secure/admin/incidents/{event_id}")
def update_incident(
    event_id: int,
    update: IncidentUpdate,
    request: Request,
    admin: AdminAccount = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
):
    event = db.query(SecurityAuditLog).filter_by(id=event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Security incident not found")
    event.incident_notes = update.notes.strip()
    event.resolved = update.resolved
    db.commit()
    record_event(db, request=request, event_type="incident_updated", status="Success", label="incident investigation updated")
    return {"id": event.id, "resolved": event.resolved, "notes": event.incident_notes}


@app.post("/secure/admin/rotate-encryption-key")
def rotate_encryption_key(
    request: Request,
    admin: AdminAccount = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
):
    try:
        _decode_key(GCM_KEY_ENV)
        rotated_credentials = 0
        rotated_mfa_seeds = 0
        for record in db.query(UserRecord).all():
            if not _uses_current_encryption_key(record.encrypted_credential):
                record.encrypted_credential = encrypt_data(decrypt_data(record.encrypted_credential))
                rotated_credentials += 1
        for account in db.query(AdminAccount).all():
            if not _uses_current_encryption_key(account.mfa_secret_encrypted):
                account.mfa_secret_encrypted = encrypt_data(decrypt_data(account.mfa_secret_encrypted))
                rotated_mfa_seeds += 1
        db.commit()
    except (RuntimeError, InvalidTag, ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Key rotation could not decrypt all protected records; no changes were applied.") from exc
    record_event(db, request=request, event_type="key_rotation", status="Success", label="encrypted records rewrapped under current key")
    return {"status": "Rotation complete", "credential_records_rotated": rotated_credentials, "mfa_seeds_rotated": rotated_mfa_seeds}


@app.get("/secure/admin/export-logs")
def export_security_logs(admin: AdminAccount = Depends(require_admin), db: Session = Depends(get_db)):
    logs = db.query(SecurityAuditLog).order_by(SecurityAuditLog.id.desc()).limit(5000).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Log ID", "Event", "Status", "Severity", "Source IP", "Pattern", "Timestamp (UTC)"])
    for log in logs:
        writer.writerow([log.id, log.event_type, log.status, log.severity, log.source_ip or "", log.pattern or "", log.timestamp])
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_audit_logs.csv"},
    )


def create_initial_admin(username: str, password: str) -> str:
    normalized_username = username.strip()
    if not normalized_username or len(normalized_username) > 128:
        raise ValueError("Username must contain between 1 and 128 characters")
    if len(password) < 14:
        raise ValueError("Administrator passwords must be at least 14 characters long")
    with SessionLocal() as db:
        if db.query(AdminAccount).count():
            raise ValueError("An administrator account already exists")
        mfa_secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        db.add(AdminAccount(
            username=normalized_username,
            password_hash=password_hasher.hash(password),
            mfa_secret_encrypted=encrypt_data(mfa_secret),
            role="admin",
        ))
        db.commit()
        return mfa_secret


def setup_admin_cli() -> None:
    parser = argparse.ArgumentParser(description="Create the first CyberGuard administrator")
    parser.add_argument("--username", required=True, help="Administrator account name")
    args = parser.parse_args()
    password = getpass.getpass("Administrator password (14+ characters): ")
    confirmation = getpass.getpass("Confirm administrator password: ")
    if not secrets.compare_digest(password, confirmation):
        parser.error("The passwords did not match")
    try:
        mfa_secret = create_initial_admin(args.username, password)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Administrator {args.username.strip()} created.")
    print("Add this TOTP seed to an authenticator now; it is shown once:")
    print(mfa_secret)
    print("The seed is encrypted in the database. Do not put it in logs or source control.")


if __name__ == "__main__":
    setup_admin_cli()
