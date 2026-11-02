import asyncio
import hmac
import importlib.metadata
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "letsrenew.sqlite3"
LE_DIR = DATA_DIR / "letsencrypt"
CREDENTIALS_DIR = Path(tempfile.gettempdir()) / "letsrenew-credentials"
PASSWORD = os.environ.get("APP_PASSWORD", "")
KEY = os.environ.get("APP_ENCRYPTION_KEY", "")
RENEW_BEFORE_DAYS = int(os.environ.get("RENEW_BEFORE_DAYS", "30"))

PROVIDER_CATALOG = [
    {"name": "IONOS", "plugin": "ionos", "package": "certbot-dns-ionos"},
    {"name": "Cloudflare", "plugin": "cloudflare", "package": "certbot-dns-cloudflare"},
    {"name": "Amazon Route 53", "plugin": "route53", "package": "certbot-dns-route53"},
    {"name": "DigitalOcean", "plugin": "digitalocean", "package": "certbot-dns-digitalocean"},
    {"name": "Google Cloud DNS", "plugin": "google", "package": "certbot-dns-google"},
    {"name": "DNSimple", "plugin": "dnsimple", "package": "certbot-dns-dnsimple"},
    {"name": "DNS Made Easy", "plugin": "dnsmadeeasy", "package": "certbot-dns-dnsmadeeasy"},
    {"name": "Gehirn", "plugin": "gehirn", "package": "certbot-dns-gehirn"},
    {"name": "Linode", "plugin": "linode", "package": "certbot-dns-linode"},
    {"name": "LuaDNS", "plugin": "luadns", "package": "certbot-dns-luadns"},
    {"name": "NS1", "plugin": "nsone", "package": "certbot-dns-nsone"},
    {"name": "OVH", "plugin": "ovh", "package": "certbot-dns-ovh"},
    {"name": "RFC 2136", "plugin": "rfc2136", "package": "certbot-dns-rfc2136"},
    {"name": "Sakura Cloud", "plugin": "sakuracloud", "package": "certbot-dns-sakuracloud"},
]
PLUGIN_INSTALL_LOCK = threading.Lock()
CERTBOT_LOCK = threading.Lock()


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize() -> Fernet:
    if not PASSWORD:
        raise RuntimeError("APP_PASSWORD must be set")
    try:
        cipher = Fernet(KEY.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("APP_ENCRYPTION_KEY must be a valid Fernet key") from exc
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if CREDENTIALS_DIR.exists():
        for stale_credential_file in CREDENTIALS_DIR.glob("provider-*.ini"):
            stale_credential_file.unlink()
    with db() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                plugin TEXT NOT NULL,
                package TEXT NOT NULL,
                config TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                domains TEXT NOT NULL,
                cert_path TEXT NOT NULL,
                key_path TEXT,
                deploy_path TEXT,
                managed INTEGER NOT NULL DEFAULT 0,
                provider_id INTEGER,
                created_at TEXT NOT NULL
            )"""
        )
    return cipher


cipher = initialize()


def decrypt_config(value: str) -> dict[str, Any]:
    try:
        return json.loads(cipher.decrypt(value.encode()).decode())
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(500, "Could not decrypt saved provider credentials") from exc


def certificate_details(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    cert_path = Path(result["cert_path"])
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        expiry = cert.not_valid_after_utc
        days_left = (expiry - datetime.now(UTC)).total_seconds() / 86400
        result.update(
            expires_at=expiry.isoformat(),
            days_left=max(0, int(days_left)),
            expired=days_left <= 0,
            available=cert_path.is_file(),
        )
    except (OSError, ValueError):
        result.update(expires_at=None, days_left=None, expired=None, available=False)
    result["managed"] = bool(result["managed"])
    result["domains"] = json.loads(result["domains"])
    return result


def ensure_plugin(package: str) -> None:
    with PLUGIN_INSTALL_LOCK:
        try:
            importlib.metadata.distribution(package)
            return
        except importlib.metadata.PackageNotFoundError:
            pass
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-input", package],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode:
            raise HTTPException(502, f"Could not install DNS plugin: {result.stderr[-2000:]}")


def write_credentials(provider_id: int, credentials: dict[str, str]) -> Path:
    if any(
        not re.fullmatch(r"[a-zA-Z0-9_-]+", key) or "\n" in value or "\r" in value
        for key, value in credentials.items()
    ):
        raise HTTPException(422, "Invalid DNS credential field")
    CREDENTIALS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    CREDENTIALS_DIR.chmod(0o700)
    credential_file = CREDENTIALS_DIR / f"provider-{provider_id}.ini"
    descriptor = os.open(credential_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as credential_stream:
        credential_stream.write("".join(f"{key} = {value}\n" for key, value in credentials.items()))
    return credential_file


def issue_certificate(
    name: str,
    domains: list[str],
    email: str,
    provider_id: int,
    deploy_path: str | None,
) -> None:
    with db() as connection:
        provider = connection.execute(
            "SELECT * FROM providers WHERE id = ?", (provider_id,)
        ).fetchone()
    if provider is None:
        raise HTTPException(404, "DNS provider not found")
    config = decrypt_config(provider["config"])
    plugin = provider["plugin"]
    ensure_plugin(provider["package"])

    credentials = config.get("credentials", {})
    options = config.get("options", {})
    credential_file = CREDENTIALS_DIR / f"provider-{provider_id}.ini"

    command = [
        "certbot",
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email",
        email,
        "--cert-name",
        name,
        "--config-dir",
        str(LE_DIR),
        "--work-dir",
        str(DATA_DIR / "work"),
        "--logs-dir",
        str(DATA_DIR / "logs"),
        "--authenticator",
        f"dns-{plugin}",
        f"--dns-{plugin}-credentials",
        str(credential_file),
    ]
    for key, value in options.items():
        if not re.fullmatch(r"[a-zA-Z0-9-]+", key):
            raise HTTPException(422, f"Invalid DNS plugin option: {key}")
        command.extend([f"--dns-{plugin}-{key}", str(value)])
    for domain in domains:
        command.extend(["-d", domain])

    with CERTBOT_LOCK:
        credential_file = write_credentials(provider_id, credentials)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        finally:
            credential_file.unlink(missing_ok=True)
    if result.returncode:
        raise HTTPException(502, f"Certificate issuance failed: {result.stderr[-3000:]}")

    cert_path = LE_DIR / "live" / name / "fullchain.pem"
    key_path = LE_DIR / "live" / name / "privkey.pem"
    deploy_certificate(cert_path, key_path, deploy_path)
    with db() as connection:
        connection.execute(
            """INSERT INTO certificates
            (name, domains, cert_path, key_path, deploy_path, managed, provider_id, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(name) DO UPDATE SET domains=excluded.domains,
                cert_path=excluded.cert_path, key_path=excluded.key_path,
                deploy_path=excluded.deploy_path, managed=1, provider_id=excluded.provider_id""",
            (
                name,
                json.dumps(domains),
                str(cert_path),
                str(key_path),
                deploy_path,
                provider_id,
                datetime.now(UTC).isoformat(),
            ),
        )


def deploy_certificate(cert_path: Path, key_path: Path, destination: str | None) -> None:
    if not destination:
        return
    target_dir = Path(destination)
    target_dir.mkdir(parents=True, exist_ok=True)
    for source, filename in ((cert_path, "fullchain.pem"), (key_path, "privkey.pem")):
        if not source.is_file():
            raise HTTPException(500, f"Certificate file is missing: {source}")
        with tempfile.NamedTemporaryFile(dir=target_dir, delete=False) as temporary:
            temporary_path = Path(temporary.name)
        shutil.copyfile(source, temporary_path)
        temporary_path.chmod(0o600 if filename == "privkey.pem" else 0o644)
        temporary_path.replace(target_dir / filename)


def run_renewal(row: sqlite3.Row, force: bool = False) -> subprocess.CompletedProcess[str]:
    with db() as connection:
        provider = connection.execute(
            "SELECT * FROM providers WHERE id = ?", (row["provider_id"],)
        ).fetchone()
    if provider is None:
        raise HTTPException(409, f"DNS provider for {row['name']} is missing")
    ensure_plugin(provider["package"])
    config = decrypt_config(provider["config"])
    command = [
        "certbot",
        "renew",
        "--non-interactive",
        "--cert-name",
        row["name"],
        "--config-dir",
        str(LE_DIR),
        "--work-dir",
        str(DATA_DIR / "work"),
        "--logs-dir",
        str(DATA_DIR / "logs"),
    ]
    if force:
        command.append("--force-renewal")
    with CERTBOT_LOCK:
        credential_file = write_credentials(provider["id"], config.get("credentials", {}))
        try:
            return subprocess.run(command, capture_output=True, text=True, timeout=1800)
        finally:
            credential_file.unlink(missing_ok=True)


def renew_due_certificates() -> None:
    with db() as connection:
        rows = connection.execute("SELECT * FROM certificates WHERE managed = 1").fetchall()
    for row in rows:
        details = certificate_details(row)
        if details["days_left"] is None or details["days_left"] > RENEW_BEFORE_DAYS:
            continue
        try:
            result = run_renewal(row)
            if result.returncode:
                print(f"Renewal failed for {row['name']}: {result.stderr[-1000:]}", flush=True)
                continue
            deploy_certificate(Path(row["cert_path"]), Path(row["key_path"]), row["deploy_path"])
        except Exception as exc:
            print(f"Renewal failed for {row['name']}: {exc}", flush=True)


async def renewal_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(renew_due_certificates)
        except Exception as exc:
            print(f"Renewal check failed: {exc}", flush=True)
        await asyncio.sleep(6 * 60 * 60)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(renewal_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="LetsRenew", lifespan=lifespan)


@app.middleware("http")
async def authenticate(request: Request, call_next):
    if request.url.path == "/api/login" or not request.url.path.startswith("/api/"):
        return await call_next(request)
    authorization = request.headers.get("authorization", "")
    supplied = authorization.removeprefix("Bearer ")
    if not hmac.compare_digest(supplied, PASSWORD):
        return await unauthorized()
    return await call_next(request)


async def unauthorized():
    from fastapi.responses import JSONResponse

    return JSONResponse({"detail": "Authentication required"}, status_code=401)


class LoginInput(BaseModel):
    password: str


class ProviderInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    plugin: str = Field(pattern=r"^[a-z0-9-]+$")
    package: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    credentials: dict[str, str] = {}
    options: dict[str, str] = {}


class ImportInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    cert_path: str
    key_path: str | None = None
    deploy_path: str | None = None


class IssueInput(BaseModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9.-]+$")
    domains: list[str] = Field(min_length=1)
    email: str
    provider_id: int
    deploy_path: str | None = None


@app.post("/api/login")
def login(data: LoginInput):
    if not hmac.compare_digest(data.password, PASSWORD):
        raise HTTPException(401, "Incorrect password")
    return {"token": PASSWORD}


@app.get("/api/certificates")
def list_certificates():
    with db() as connection:
        rows = connection.execute("SELECT * FROM certificates ORDER BY name").fetchall()
    return [certificate_details(row) for row in rows]


@app.post("/api/certificates/import")
def import_certificate(data: ImportInput):
    cert_path = Path(data.cert_path)
    if not cert_path.is_file():
        raise HTTPException(422, "Certificate file does not exist")
    try:
        x509.load_pem_x509_certificate(cert_path.read_bytes())
    except ValueError as exc:
        raise HTTPException(422, "File is not a valid PEM certificate") from exc
    if data.key_path and not Path(data.key_path).is_file():
        raise HTTPException(422, "Private key file does not exist")
    with db() as connection:
        connection.execute(
            """INSERT INTO certificates
            (name, domains, cert_path, key_path, deploy_path, managed, created_at)
            VALUES (?, '[]', ?, ?, ?, 0, ?)
            ON CONFLICT(name) DO UPDATE SET cert_path=excluded.cert_path,
                key_path=excluded.key_path, deploy_path=excluded.deploy_path, managed=0""",
            (
                data.name,
                str(cert_path),
                data.key_path,
                data.deploy_path,
                datetime.now(UTC).isoformat(),
            ),
        )
    return {"status": "imported"}


@app.delete("/api/certificates/{certificate_id}")
def delete_certificate(certificate_id: int):
    with db() as connection:
        cursor = connection.execute("DELETE FROM certificates WHERE id = ?", (certificate_id,))
    if not cursor.rowcount:
        raise HTTPException(404, "Certificate not found")
    return {"status": "deleted"}


@app.get("/api/providers/catalog")
def provider_catalog():
    return PROVIDER_CATALOG


@app.get("/api/providers")
def list_providers():
    with db() as connection:
        providers = connection.execute(
            "SELECT id, name, plugin, package, config FROM providers ORDER BY name"
        ).fetchall()
    return [
        {
            "id": provider["id"],
            "name": provider["name"],
            "plugin": provider["plugin"],
            "package": provider["package"],
            "has_credentials": bool(decrypt_config(provider["config"]).get("credentials")),
        }
        for provider in providers
    ]


@app.post("/api/providers")
def save_provider(data: ProviderInput):
    config = cipher.encrypt(
        json.dumps(
            {"credentials": data.credentials, "options": data.options},
            separators=(",", ":"),
        ).encode()
    ).decode()
    with db() as connection:
        cursor = connection.execute(
            "INSERT INTO providers (name, plugin, package, config) VALUES (?, ?, ?, ?)",
            (data.name, data.plugin, data.package, config),
        )
        provider_id = cursor.lastrowid
    return {"id": provider_id}


@app.delete("/api/providers/{provider_id}")
def delete_provider(provider_id: int):
    with db() as connection:
        managed_certificates = connection.execute(
            "SELECT COUNT(*) FROM certificates WHERE provider_id = ? AND managed = 1",
            (provider_id,),
        ).fetchone()[0]
        if managed_certificates:
            raise HTTPException(
                409, "DNS provider is used by managed certificates; change those certificates first"
            )
        cursor = connection.execute("DELETE FROM providers WHERE id = ?", (provider_id,))
    if not cursor.rowcount:
        raise HTTPException(404, "DNS provider not found")
    return {"status": "deleted"}


@app.post("/api/providers/{provider_id}/install")
def install_provider(provider_id: int):
    with db() as connection:
        provider = connection.execute(
            "SELECT package FROM providers WHERE id = ?", (provider_id,)
        ).fetchone()
    if provider is None:
        raise HTTPException(404, "DNS provider not found")
    ensure_plugin(provider["package"])
    return {"status": "installed"}


@app.post("/api/certificates/issue", status_code=202)
async def issue(data: IssueInput):
    domains = [domain.strip().lower() for domain in data.domains]
    if any(not re.fullmatch(r"\*\.[a-z0-9.-]+|[a-z0-9.-]+", domain) for domain in domains):
        raise HTTPException(422, "One or more domain names are invalid")
    await asyncio.to_thread(
        issue_certificate, data.name, domains, data.email, data.provider_id, data.deploy_path
    )
    return {"status": "issued"}


@app.post("/api/certificates/{certificate_id}/renew")
async def renew(certificate_id: int):
    with db() as connection:
        row = connection.execute(
            "SELECT * FROM certificates WHERE id = ? AND managed = 1", (certificate_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Managed certificate not found")
    result = await asyncio.to_thread(run_renewal, row, True)
    if result.returncode:
        raise HTTPException(502, f"Certificate renewal failed: {result.stderr[-3000:]}")
    await asyncio.to_thread(
        deploy_certificate, Path(row["cert_path"]), Path(row["key_path"]), row["deploy_path"]
    )
    return {"status": "renewed"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


STATIC_DIR = Path(__file__).with_name("static")


def mount_static_files(target_app: FastAPI, static_dir: Path = STATIC_DIR) -> None:
    if static_dir.is_dir():
        target_app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")


mount_static_files(app)
