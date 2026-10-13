import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import main


@pytest.fixture
def service_client(monkeypatch):
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    main.Base.metadata.create_all(bind=test_engine)
    test_sessions = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    monkeypatch.setattr(main, "SessionLocal", test_sessions)
    monkeypatch.setattr(main, "CLIENT_CAPABILITY_CODE", "test-client-capability")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("AES_256_GCM_KEY", base64.urlsafe_b64encode(b"K" * 32).decode("ascii").rstrip("="))
    main.create_initial_admin("test-admin", "test-admin-password-strong")
    with TestClient(main.app) as client:
        yield client, test_sessions
    test_engine.dispose()


def login_admin(client, sessions):
    with sessions() as db:
        admin = db.query(main.AdminAccount).filter_by(username="test-admin").one()
        mfa_secret = main.decrypt_data(admin.mfa_secret_encrypted)
    response = client.post(
        "/secure/admin/login",
        json={
            "username": "test-admin",
            "password": "test-admin-password-strong",
            "totp_code": main._totp_code(mfa_secret),
        },
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "alice UNION/**/SELECT password FROM users",
        "admin%27%20OR%201%3D1%20--",
        "Robert'); DROP TABLE users;--",
        "name--comment",
    ],
)
def test_detector_classifies_common_injection(payload):
    assert main.detect_sql_injection(payload)


@pytest.mark.parametrize("username", ["alice", "alex.morgan", "orville-lee", "customer_42"])
def test_detector_allows_ordinary_usernames(username):
    assert main.detect_sql_injection(username) == []


def test_aes_gcm_detects_ciphertext_tampering(monkeypatch):
    monkeypatch.setenv("AES_256_GCM_KEY", base64.urlsafe_b64encode(b"T" * 32).decode("ascii").rstrip("="))
    encrypted = main.encrypt_data("sensitive-value")
    assert main.decrypt_data(encrypted) == "sensitive-value"
    encoded = encrypted[3:]
    raw = bytearray(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    raw[12] ^= 1
    corrupted = "v2:" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    with pytest.raises(Exception):
        main.decrypt_data(corrupted)


def test_legacy_cfb_data_can_be_read_for_rotation(monkeypatch):
    legacy_key = b"L" * 32
    iv = b"I" * 16
    encryptor = Cipher(algorithms.AES(legacy_key), modes.CFB(iv)).encryptor()
    ciphertext = encryptor.update(b"legacy-secret") + encryptor.finalize()
    monkeypatch.setenv("LEGACY_AES_KEY", legacy_key.decode("ascii"))
    monkeypatch.setenv("AES_256_GCM_KEY", base64.urlsafe_b64encode(b"N" * 32).decode("ascii").rstrip("="))
    legacy_record = base64.b64encode(iv + ciphertext).decode("ascii")
    plaintext = main.decrypt_data(legacy_record)
    assert plaintext == "legacy-secret"
    assert main.decrypt_data(main.encrypt_data(plaintext)) == plaintext


def test_aes_gcm_reads_previous_rotation_key(monkeypatch):
    old_key = base64.urlsafe_b64encode(b"O" * 32).decode("ascii").rstrip("=")
    new_key = base64.urlsafe_b64encode(b"N" * 32).decode("ascii").rstrip("=")
    monkeypatch.setenv("AES_256_GCM_KEY", old_key)
    encrypted = main.encrypt_data("rotate-me")
    monkeypatch.setenv("AES_256_GCM_KEY", new_key)
    monkeypatch.setenv("AES_256_GCM_PREVIOUS_KEYS", old_key)
    assert main.decrypt_data(encrypted) == "rotate-me"
    assert main.encrypt_data("rotate-me") != encrypted


def test_admin_key_rotation_rewraps_credentials_and_mfa_seeds(service_client, monkeypatch):
    client, sessions = service_client
    with sessions() as db:
        db.add(main.UserRecord(username="rotation-target", encrypted_credential=main.encrypt_data("protected-value")))
        db.commit()
    csrf = login_admin(client, sessions)
    current_key = base64.urlsafe_b64encode(b"N" * 32).decode("ascii").rstrip("=")
    old_key = base64.urlsafe_b64encode(b"K" * 32).decode("ascii").rstrip("=")
    monkeypatch.setenv("AES_256_GCM_KEY", current_key)
    monkeypatch.setenv("AES_256_GCM_PREVIOUS_KEYS", old_key)
    denied = client.post("/secure/admin/rotate-encryption-key")
    assert denied.status_code == 403
    rotated = client.post("/secure/admin/rotate-encryption-key", headers={"x-csrf-token": csrf})
    assert rotated.status_code == 200
    assert rotated.json() == {
        "status": "Rotation complete",
        "credential_records_rotated": 1,
        "mfa_seeds_rotated": 1,
    }
    monkeypatch.delenv("AES_256_GCM_PREVIOUS_KEYS")
    with sessions() as db:
        record = db.query(main.UserRecord).filter_by(username="rotation-target").one()
        account = db.query(main.AdminAccount).filter_by(username="test-admin").one()
        assert main._uses_current_encryption_key(record.encrypted_credential)
        assert main._uses_current_encryption_key(account.mfa_secret_encrypted)
        assert main.decrypt_data(record.encrypted_credential) == "protected-value"


def test_client_can_store_and_retrieve_but_admin_data_is_separate(service_client):
    client, sessions = service_client
    client_headers = {"x-capability-code": "test-client-capability"}
    stored = client.post(
        "/secure/store",
        headers=client_headers,
        json={"username": "alice", "sensitive_credential": "private-value"},
    )
    assert stored.status_code == 200
    assert "private-value" not in stored.text
    retrieved = client.post("/secure/retrieve", headers=client_headers, json={"username": "alice"})
    assert retrieved.status_code == 200
    assert retrieved.json()["decrypted_plain_text"] == "private-value"

    denied = client.get("/secure/admin/dashboard-data", headers=client_headers)
    assert denied.status_code == 401
    login_admin(client, sessions)
    dashboard = client.get("/secure/admin/dashboard-data")
    assert dashboard.status_code == 200
    body = dashboard.json()
    assert body["database_activity"] == {"stored": 1, "retrieved": 1}
    assert body["total_users"] == 1
    assert body["successful_authentication_attempts"] == 2
    assert body["cloud_security"]["cloud_provider"] == "Not integrated"
    assert body["product"]["license"] == "community"
    assert "encrypted_credential" not in dashboard.text
    assert "private-value" not in dashboard.text
    with sessions() as db:
        record = db.query(main.UserRecord).one()
        assert record.encrypted_credential.startswith("v2:")


def test_injection_is_blocked_and_payload_is_not_audited(service_client):
    client, sessions = service_client
    payload = "' OR '1'='1 -- private@example.test"
    response = client.post(
        "/secure/retrieve",
        headers={"x-capability-code": "test-client-capability"},
        json={"username": payload},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "Blocked"
    with sessions() as db:
        event = db.query(main.SecurityAuditLog).filter_by(event_type="sql_injection").one()
        assert payload not in event.attempted_input
        assert "private@example.test" not in event.pattern
        assert event.severity == "high"


def test_wrong_capability_is_logged_without_logging_the_secret(service_client):
    client, sessions = service_client
    response = client.post(
        "/secure/store",
        headers={"x-capability-code": "do-not-log-this"},
        json={"username": "alice", "sensitive_credential": "secret"},
    )
    assert response.status_code == 403
    with sessions() as db:
        event = db.query(main.SecurityAuditLog).filter_by(event_type="unauthorized_access").one()
        assert "do-not-log-this" not in event.attempted_input


def test_export_requires_admin_header_and_returns_redacted_events(service_client):
    client, sessions = service_client
    denied = client.get("/secure/admin/export-logs")
    assert denied.status_code == 401
    login_admin(client, sessions)
    allowed = client.get("/secure/admin/export-logs")
    assert allowed.status_code == 200
    assert "Event,Status,Severity" in allowed.text
    assert "test-admin-password-strong" not in allowed.text


def test_admin_login_requires_mfa_and_logout_revokes_session(service_client):
    client, sessions = service_client
    with sessions() as db:
        admin = db.query(main.AdminAccount).one()
        mfa_secret = main.decrypt_data(admin.mfa_secret_encrypted)
    failed = client.post("/secure/admin/login", json={
        "username": "test-admin", "password": "test-admin-password-strong", "totp_code": "000000",
    })
    assert failed.status_code == 401
    logged_in = client.post("/secure/admin/login", json={
        "username": "test-admin", "password": "test-admin-password-strong", "totp_code": main._totp_code(mfa_secret),
    })
    assert logged_in.status_code == 200
    assert "httponly" in logged_in.headers["set-cookie"].lower()
    csrf = logged_in.json()["csrf_token"]
    assert client.get("/secure/admin/session").json()["role"] == "admin"
    logout = client.post("/secure/admin/logout", headers={"x-csrf-token": csrf})
    assert logout.status_code == 200
    assert client.get("/secure/admin/dashboard-data").status_code == 401


def test_admin_account_locks_after_configured_failed_attempts(service_client, monkeypatch):
    client, sessions = service_client
    monkeypatch.setenv("ADMIN_ACCOUNT_LOCKOUT_THRESHOLD", "3")
    with sessions() as db:
        admin = db.query(main.AdminAccount).one()
        mfa_secret = main.decrypt_data(admin.mfa_secret_encrypted)
    for _ in range(3):
        response = client.post("/secure/admin/login", json={
            "username": "test-admin", "password": "incorrect-password-long", "totp_code": "000000",
        })
        assert response.status_code == 401
    assert client.post("/secure/admin/login", json={
        "username": "test-admin",
        "password": "test-admin-password-strong",
        "totp_code": main._totp_code(mfa_secret),
    }).status_code == 401
    with sessions() as db:
        assert db.query(main.AdminAccount).one().locked_until is not None


def test_admin_mutations_require_csrf_and_incidents_are_investigable(service_client):
    client, sessions = service_client
    with sessions() as db:
        event = main.SecurityAuditLog(event_type="sql_injection", status="Blocked", severity="high", attempted_input="redacted")
        db.add(event)
        db.commit()
        event_id = event.id
    assert client.patch(f"/secure/admin/incidents/{event_id}", json={"notes": "reviewed", "resolved": True}).status_code == 401
    csrf = login_admin(client, sessions)
    assert client.patch(
        f"/secure/admin/incidents/{event_id}",
        headers={"x-csrf-token": csrf},
        json={"notes": "Reviewed source and blocked payload.", "resolved": True},
    ).json() == {"id": event_id, "resolved": True, "notes": "Reviewed source and blocked payload."}


def test_help_endpoint_explains_the_search_and_security_flow(service_client):
    client, _ = service_client
    response = client.get("/secure/help")
    assert response.status_code == 200
    payload = response.json()
    assert "search" in payload["plain_language"].lower()
    assert any("store" in step["title"].lower() for step in payload["steps"])
    assert any("admin" in task["label"].lower() for task in payload["common_tasks"])


def test_admin_setup_rejects_weak_or_duplicate_accounts(service_client):
    _, _ = service_client
    with pytest.raises(ValueError, match="14 characters"):
        main.create_initial_admin("another-admin", "short")
    with pytest.raises(ValueError, match="already exists"):
        main.create_initial_admin("another-admin", "another-admin-password-long")


def test_validation_errors_do_not_echo_sensitive_input(service_client):
    client, _ = service_client
    sensitive_value = 12345678901234567890
    response = client.post(
        "/secure/store",
        headers={"x-capability-code": "test-client-capability"},
        json={"username": "alice", "sensitive_credential": 12345678901234567890},
    )
    assert response.status_code == 422
    assert str(sensitive_value) not in response.text
    assert "input" not in response.json()["detail"][0]


@pytest.mark.parametrize("path,body", [
    ("/secure/store", {"username": "   ", "sensitive_credential": "value"}),
    ("/secure/retrieve", {"username": "   "}),
])
def test_username_validation_rejects_whitespace_only(path, body, service_client):
    client, _ = service_client
    response = client.post(path, headers={"x-capability-code": "test-client-capability"}, json=body)
    assert response.status_code == 422


def test_health_endpoint_reports_configured_controls(service_client):
    client, _ = service_client
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": "1.0.0",
        "database": "operational",
        "encryption": "configured",
    }


def test_admin_dashboard_does_not_return_legacy_attempted_input(service_client):
    client, sessions = service_client
    with sessions() as db:
        db.add(main.SecurityAuditLog(
            attempted_input="potentially-sensitive-old-payload",
            event_type="legacy",
            status="Recorded",
            severity="info",
        ))
        db.commit()
    login_admin(client, sessions)
    response = client.get("/secure/admin/dashboard-data")
    assert response.status_code == 200
    assert "potentially-sensitive-old-payload" not in response.text
    assert "attempted_input" not in response.text


def test_repeated_normal_requests_do_not_become_security_alerts(service_client):
    _, sessions = service_client
    request = main.Request({
        "type": "http", "method": "GET", "path": "/healthz", "headers": [],
        "client": ("127.0.0.1", 1234), "server": ("testserver", 80),
        "scheme": "http", "query_string": b"",
    })
    with sessions() as db:
        for _ in range(6):
            main.record_event(
                db,
                request=request,
                event_type="request_monitored",
                status="HTTP 200",
                label="GET /healthz",
            )
        ordinary = db.query(main.SecurityAuditLog).filter_by(event_type="request_monitored").first()
        assert ordinary.severity == "info"


def test_repeated_attack_events_escalate_to_critical(service_client):
    _, sessions = service_client
    request = main.Request({
        "type": "http", "method": "POST", "path": "/secure/retrieve", "headers": [],
        "client": ("192.0.2.44", 1234), "server": ("testserver", 80),
        "scheme": "http", "query_string": b"",
    })
    with sessions() as db:
        events = [main.record_event(
            db,
            request=request,
            event_type="sql_injection",
            status="Blocked",
            label="suspicious query input redacted",
            severity="high",
        ) for _ in range(5)]
        assert events[-1].severity == "critical"