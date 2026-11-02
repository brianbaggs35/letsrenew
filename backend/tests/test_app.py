import asyncio
import json
import os
import stat
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

TEST_DATA_DIR = tempfile.TemporaryDirectory(prefix="letsrenew-test-")
os.environ["DATA_DIR"] = TEST_DATA_DIR.name
os.environ["APP_PASSWORD"] = "test-admin-password"
os.environ["APP_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import app as application  # noqa: E402
from app import app, db  # noqa: E402


@pytest.fixture
def client():
    with db() as connection:
        connection.execute("DELETE FROM certificates")
        connection.execute("DELETE FROM providers")
    with TestClient(app) as test_client:
        yield test_client


def auth(password="test-admin-password"):
    return {"Authorization": f"Bearer {password}"}


def test_login_rejects_bad_password_and_accepts_good_one(client):
    assert client.post("/api/login", json={"password": "wrong"}).status_code == 401
    response = client.post("/api/login", json={"password": "test-admin-password"})
    assert response.status_code == 200
    assert response.json()["token"] == "test-admin-password"


def test_api_requires_authentication(client):
    assert client.get("/api/certificates").status_code == 401
    assert client.get("/api/certificates", headers=auth()).status_code == 200


def test_provider_credentials_are_encrypted_in_database(client):
    response = client.post(
        "/api/providers",
        headers=auth(),
        json={
            "name": "Test DNS",
            "plugin": "test",
            "package": "certbot-dns-test",
            "credentials": {"api_secret": "this-is-a-secret"},
            "options": {},
        },
    )
    assert response.status_code == 200
    with db() as connection:
        stored = connection.execute(
            "SELECT config FROM providers WHERE id = ?", (response.json()["id"],)
        ).fetchone()["config"]
    assert "this-is-a-secret" not in stored
    providers = client.get("/api/providers", headers=auth()).json()
    assert providers[0]["has_credentials"] is True
    assert "this-is-a-secret" not in str(providers)


def test_imported_certificate_is_tracked_with_expiry(client):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=60))
        .sign(private_key, hashes.SHA256())
    )
    cert_path = Path(os.environ["DATA_DIR"]) / "monitor.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    response = client.post(
        "/api/certificates/import",
        headers=auth(),
        json={"name": "Test certificate", "cert_path": str(cert_path)},
    )
    assert response.status_code == 200
    tracked = client.get("/api/certificates", headers=auth()).json()[0]
    assert tracked["available"] is True
    assert tracked["managed"] is False
    assert 58 <= tracked["days_left"] <= 60


def make_certificate(path: Path, expires_in_days: int = 60) -> Path:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            now + timedelta(days=expires_in_days - 2)
            if expires_in_days < 0
            else now - timedelta(minutes=1)
        )
        .not_valid_after(now + timedelta(days=expires_in_days))
        .sign(private_key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path


def create_provider(client, credentials=None):
    response = client.post(
        "/api/providers",
        headers=auth(),
        json={
            "name": "Test DNS",
            "plugin": "test",
            "package": "certbot-dns-test",
            "credentials": {"api_secret": "secret"} if credentials is None else credentials,
            "options": {},
        },
    )
    assert response.status_code == 200
    return response.json()["id"]


def insert_certificate(
    name="managed.example",
    cert_path="/missing/cert.pem",
    key_path="/missing/key.pem",
    deploy_path=None,
    provider_id=1,
):
    with db() as connection:
        cursor = connection.execute(
            """INSERT INTO certificates
            (name, domains, cert_path, key_path, deploy_path, managed, provider_id, created_at)
            VALUES (?, '[]', ?, ?, ?, 1, ?, ?)""",
            (
                name,
                cert_path,
                key_path,
                deploy_path,
                provider_id,
                datetime.now(UTC).isoformat(),
            ),
        )
        return cursor.lastrowid


def test_certificate_details_reports_missing_and_expired_files(tmp_path):
    missing = {
        "id": 1,
        "name": "missing",
        "domains": "[]",
        "cert_path": str(tmp_path / "missing.pem"),
        "key_path": None,
        "deploy_path": None,
        "managed": 0,
    }
    result = application.certificate_details(missing)
    assert result["available"] is False
    assert result["expires_at"] is None
    assert result["managed"] is False

    expired_path = make_certificate(tmp_path / "expired.pem", -1)
    missing["cert_path"] = str(expired_path)
    missing["managed"] = 1
    result = application.certificate_details(missing)
    assert result["expired"] is True
    assert result["days_left"] == 0
    assert result["managed"] is True


def test_database_rolls_back_exceptions():
    with pytest.raises(RuntimeError, match="rollback"):
        with db() as connection:
            connection.execute(
                "INSERT INTO providers "
                "(name, plugin, package, config) VALUES ('rollback', 'p', 'p', 'x')"
            )
            raise RuntimeError("rollback")
    with db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM providers").fetchone()[0] == 0


def test_write_credentials_validates_values_and_sets_private_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(application, "CREDENTIALS_DIR", tmp_path / "secure")
    with pytest.raises(application.HTTPException, match="Invalid DNS credential field"):
        application.write_credentials(1, {"bad key": "secret"})
    with pytest.raises(application.HTTPException, match="Invalid DNS credential field"):
        application.write_credentials(1, {"valid": "secret\ninjected = true"})

    credential_file = application.write_credentials(12, {"api_secret": "a secret"})
    assert credential_file.read_text() == "api_secret = a secret\n"
    assert stat.S_IMODE(credential_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(credential_file.parent.stat().st_mode) == 0o700


def test_ensure_plugin_skips_installed_package_and_installs_missing_one(monkeypatch):
    distribution = Mock()
    monkeypatch.setattr(application.importlib.metadata, "distribution", distribution)
    run = Mock()
    monkeypatch.setattr(application.subprocess, "run", run)
    application.ensure_plugin("already-installed")
    run.assert_not_called()

    distribution.side_effect = application.importlib.metadata.PackageNotFoundError
    run.return_value = subprocess.CompletedProcess([], 0, "", "")
    application.ensure_plugin("missing-plugin")
    assert run.call_args.args[0][-1] == "missing-plugin"

    run.return_value = subprocess.CompletedProcess([], 1, "", "install failed")
    with pytest.raises(application.HTTPException, match="Could not install DNS plugin"):
        application.ensure_plugin("broken-plugin")


def test_deploy_certificate_copies_files_with_secure_modes(tmp_path):
    cert = tmp_path / "source-cert.pem"
    key = tmp_path / "source-key.pem"
    cert.write_text("certificate")
    key.write_text("private key")
    application.deploy_certificate(cert, key, None)
    with pytest.raises(application.HTTPException, match="Certificate file is missing"):
        application.deploy_certificate(tmp_path / "missing", key, str(tmp_path / "deploy"))

    destination = tmp_path / "deploy"
    application.deploy_certificate(cert, key, str(destination))
    assert (destination / "fullchain.pem").read_text() == "certificate"
    assert (destination / "privkey.pem").read_text() == "private key"
    assert stat.S_IMODE((destination / "fullchain.pem").stat().st_mode) == 0o644
    assert stat.S_IMODE((destination / "privkey.pem").stat().st_mode) == 0o600


def test_issue_certificate_runs_certbot_and_persists_certificate(client, monkeypatch, tmp_path):
    provider_id = create_provider(client, {"dns_token": "safe"})
    monkeypatch.setattr(application, "ensure_plugin", lambda package: None)
    monkeypatch.setattr(
        application.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    monkeypatch.setattr(application, "LE_DIR", tmp_path / "letsencrypt")

    original_run = application.subprocess.run
    commands = []

    def record_run(command, **kwargs):
        commands.append(command)
        return original_run(command, **kwargs)

    monkeypatch.setattr(application.subprocess, "run", record_run)
    application.issue_certificate(
        "test.example",
        ["test.example", "*.test.example"],
        "admin@example.test",
        provider_id,
        None,
    )
    assert "--dns-test-credentials" in commands[0]
    assert "-d" in commands[0]
    assert not list(application.CREDENTIALS_DIR.glob("provider-*.ini"))
    managed = client.get("/api/certificates", headers=auth()).json()
    assert managed[0]["managed"] is True
    assert managed[0]["domains"] == ["test.example", "*.test.example"]


def test_initialize_validates_configuration_and_cleans_stale_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(application, "PASSWORD", "")
    with pytest.raises(RuntimeError, match="APP_PASSWORD must be set"):
        application.initialize()

    monkeypatch.setattr(application, "PASSWORD", "test-password")
    monkeypatch.setattr(application, "KEY", "invalid-key")
    with pytest.raises(RuntimeError, match="APP_ENCRYPTION_KEY must be a valid Fernet key"):
        application.initialize()

    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    stale_file = credentials_dir / "provider-99.ini"
    stale_file.write_text("stale")
    (credentials_dir / "keep.txt").write_text("keep")
    monkeypatch.setattr(application, "KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(application, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(application, "DB_PATH", tmp_path / "data" / "test.sqlite3")
    monkeypatch.setattr(application, "CREDENTIALS_DIR", credentials_dir)
    application.initialize()
    assert not stale_file.exists()
    assert (credentials_dir / "keep.txt").exists()


def test_issue_certificate_rejects_bad_options_and_cleans_credentials(client, monkeypatch):
    provider_id = create_provider(client)
    with db() as connection:
        encrypted = application.cipher.encrypt(
            json.dumps({"credentials": {}, "options": {"bad option": "value"}}).encode()
        ).decode()
        connection.execute("UPDATE providers SET config = ? WHERE id = ?", (encrypted, provider_id))
    monkeypatch.setattr(application, "ensure_plugin", lambda package: None)
    with pytest.raises(application.HTTPException, match="Invalid DNS plugin option"):
        application.issue_certificate(
            "test.example", ["test.example"], "a@b.test", provider_id, None
        )

    with db() as connection:
        connection.execute(
            "UPDATE providers SET config = ? WHERE id = ?",
            (
                application.cipher.encrypt(b'{"credentials":{},"options":{}}').decode(),
                provider_id,
            ),
        )
    monkeypatch.setattr(
        application.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", "certbot failed"),
    )
    with pytest.raises(application.HTTPException, match="Certificate issuance failed"):
        application.issue_certificate(
            "test.example", ["test.example"], "a@b.test", provider_id, None
        )
    assert not list(application.CREDENTIALS_DIR.glob("provider-*.ini"))


def test_decrypt_config_rejects_invalid_ciphertext():
    with pytest.raises(
        application.HTTPException, match="Could not decrypt saved provider credentials"
    ):
        application.decrypt_config("not-encrypted")


def test_run_renewal_checks_provider_and_supports_force(client, monkeypatch):
    provider_id = create_provider(client)
    certificate_id = insert_certificate(provider_id=provider_id)
    with db() as connection:
        row = connection.execute(
            "SELECT * FROM certificates WHERE id = ?", (certificate_id,)
        ).fetchone()
    monkeypatch.setattr(application, "ensure_plugin", lambda package: None)
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(application.subprocess, "run", run)
    assert application.run_renewal(row).returncode == 0
    assert "--force-renewal" not in commands[-1]
    assert application.run_renewal(row, True).returncode == 0
    assert "--force-renewal" in commands[-1]

    with db() as connection:
        connection.execute("DELETE FROM providers")
    with pytest.raises(application.HTTPException, match="DNS provider .* is missing"):
        application.run_renewal(row)


def test_issue_certificate_not_found_and_valid_plugin_options(client, monkeypatch):
    with pytest.raises(application.HTTPException, match="DNS provider not found"):
        application.issue_certificate("missing.example", ["missing.example"], "a@b.test", 999, None)

    provider_id = create_provider(client)
    with db() as connection:
        encrypted = application.cipher.encrypt(
            json.dumps(
                {"credentials": {"token": "secret"}, "options": {"propagation-seconds": "60"}}
            ).encode()
        ).decode()
        connection.execute("UPDATE providers SET config = ? WHERE id = ?", (encrypted, provider_id))
    monkeypatch.setattr(application, "ensure_plugin", lambda package: None)
    command_record = []
    monkeypatch.setattr(
        application.subprocess,
        "run",
        lambda command, **kwargs: (
            command_record.append(command) or subprocess.CompletedProcess(command, 0, "", "")
        ),
    )
    application.issue_certificate("valid.example", ["valid.example"], "a@b.test", provider_id, None)
    assert "--dns-test-propagation-seconds" in command_record[0]


def test_renew_due_certificates_skips_not_due_and_handles_failure(client, monkeypatch, capsys):
    provider_id = create_provider(client)
    insert_certificate("future.example", provider_id=provider_id)
    insert_certificate("invalid.example", provider_id=provider_id)
    insert_certificate("due.example", provider_id=provider_id)
    details = iter(
        [
            {"days_left": 90},
            {"days_left": None},
            {"days_left": 2},
        ]
    )
    monkeypatch.setattr(application, "certificate_details", lambda row: next(details))
    calls = []

    def renew(row):
        calls.append(row["name"])
        if row["name"] == "due.example":
            return subprocess.CompletedProcess([], 1, "", "renew failed")
        raise AssertionError("Unexpected renewal")

    monkeypatch.setattr(application, "run_renewal", renew)
    application.renew_due_certificates()
    assert calls == ["due.example"]
    assert "Renewal failed for due.example" in capsys.readouterr().out


def test_renew_due_certificates_deploys_success_and_logs_exception(client, monkeypatch, capsys):
    provider_id = create_provider(client)
    insert_certificate("success.example", provider_id=provider_id)
    insert_certificate("exception.example", provider_id=provider_id)
    monkeypatch.setattr(application, "certificate_details", lambda row: {"days_left": 1})

    def renew(row):
        if row["name"] == "exception.example":
            raise RuntimeError("renewal crashed")
        return subprocess.CompletedProcess([], 0, "", "")

    deployments = []
    monkeypatch.setattr(application, "run_renewal", renew)
    monkeypatch.setattr(application, "deploy_certificate", lambda *args: deployments.append(args))
    application.renew_due_certificates()
    assert len(deployments) == 1
    assert "Renewal failed for exception.example: renewal crashed" in capsys.readouterr().out


def test_renewal_loop_continues_after_failure(monkeypatch, capsys):
    calls = []

    def renew():
        calls.append(True)
        raise RuntimeError("loop failure")

    async def stop(_):
        raise asyncio.CancelledError

    monkeypatch.setattr(application, "renew_due_certificates", renew)
    monkeypatch.setattr(application.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(application.renewal_loop())
    assert calls == [True]
    assert "Renewal check failed: loop failure" in capsys.readouterr().out


def test_provider_catalog_and_provider_lifecycle(client, monkeypatch):
    catalog = client.get("/api/providers/catalog", headers=auth())
    assert any(item["plugin"] == "ionos" for item in catalog.json())
    assert client.post("/api/providers/999/install", headers=auth()).status_code == 404

    provider_id = create_provider(client, {})
    assert client.get("/api/providers", headers=auth()).json()[0]["has_credentials"] is False
    installed = Mock()
    monkeypatch.setattr(application, "ensure_plugin", installed)
    assert (
        client.post(f"/api/providers/{provider_id}/install", headers=auth()).json()["status"]
        == "installed"
    )
    installed.assert_called_once_with("certbot-dns-test")

    assert (
        client.delete(f"/api/providers/{provider_id}", headers=auth()).json()["status"] == "deleted"
    )
    assert client.delete(f"/api/providers/{provider_id}", headers=auth()).status_code == 404


def test_provider_cannot_be_deleted_when_used_by_managed_certificate(client):
    provider_id = create_provider(client)
    insert_certificate(provider_id=provider_id)
    response = client.delete(f"/api/providers/{provider_id}", headers=auth())
    assert response.status_code == 409


def test_certificate_import_errors_and_upsert(client, tmp_path):
    headers = auth()
    missing = client.post(
        "/api/certificates/import",
        headers=headers,
        json={"name": "missing", "cert_path": str(tmp_path / "missing.pem")},
    )
    assert missing.status_code == 422
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not a certificate")
    assert (
        client.post(
            "/api/certificates/import",
            headers=headers,
            json={"name": "invalid", "cert_path": str(invalid)},
        ).status_code
        == 422
    )
    cert_path = make_certificate(tmp_path / "cert.pem")
    assert (
        client.post(
            "/api/certificates/import",
            headers=headers,
            json={"name": "missing key", "cert_path": str(cert_path), "key_path": "/missing/key"},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/certificates/import",
            headers=headers,
            json={"name": "imported", "cert_path": str(cert_path)},
        ).status_code
        == 200
    )
    replacement = make_certificate(tmp_path / "replacement.pem", 90)
    assert (
        client.post(
            "/api/certificates/import",
            headers=headers,
            json={"name": "imported", "cert_path": str(replacement)},
        ).status_code
        == 200
    )
    tracked = client.get("/api/certificates", headers=headers).json()
    assert len(tracked) == 1 and tracked[0]["cert_path"] == str(replacement)


def test_issue_route_validates_domains_and_calls_issuer(client, monkeypatch):
    assert (
        client.post(
            "/api/certificates/issue",
            headers=auth(),
            json={"name": "a", "domains": ["invalid domain"], "email": "a@b", "provider_id": 1},
        ).status_code
        == 422
    )
    called = []
    monkeypatch.setattr(application, "issue_certificate", lambda *args: called.append(args))
    response = client.post(
        "/api/certificates/issue",
        headers=auth(),
        json={
            "name": "example.com",
            "domains": ["EXAMPLE.com", "*.example.com"],
            "email": "admin@example.com",
            "provider_id": 2,
            "deploy_path": "/deploy",
        },
    )
    assert response.status_code == 202
    assert called[0][1] == ["example.com", "*.example.com"]


def test_renew_route_success_errors_and_not_found(client, monkeypatch):
    assert client.post("/api/certificates/999/renew", headers=auth()).status_code == 404
    provider_id = create_provider(client)
    certificate_id = insert_certificate(provider_id=provider_id)
    monkeypatch.setattr(
        application,
        "run_renewal",
        lambda row, force: subprocess.CompletedProcess([], 0, "", ""),
    )
    deployments = []
    monkeypatch.setattr(application, "deploy_certificate", lambda *args: deployments.append(args))
    response = client.post(f"/api/certificates/{certificate_id}/renew", headers=auth())
    assert response.status_code == 200
    assert len(deployments) == 1

    monkeypatch.setattr(
        application,
        "run_renewal",
        lambda row, force: subprocess.CompletedProcess([], 1, "", "renew failed"),
    )
    response = client.post(f"/api/certificates/{certificate_id}/renew", headers=auth())
    assert response.status_code == 502


def test_delete_certificate_and_health(client):
    certificate_id = insert_certificate()
    assert client.delete(f"/api/certificates/{certificate_id}", headers=auth()).status_code == 200
    assert client.delete("/api/certificates/999", headers=auth()).status_code == 404
    assert client.get("/api/health", headers=auth()).json() == {"status": "ok"}


def test_static_file_mount_uses_existing_directory(tmp_path):
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    target_app = application.FastAPI()
    application.mount_static_files(target_app, static_dir)
    assert target_app.routes[-1].path == ""

    empty_app = application.FastAPI()
    application.mount_static_files(empty_app, tmp_path / "missing")
    assert len(empty_app.routes) == 4
