import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

from app import app, db  # noqa: E402


@pytest.fixture
def client():
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
    now = datetime.now(timezone.utc)
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
