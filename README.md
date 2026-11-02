# LetsRenew

LetsRenew is a single-container certificate manager with a Vue/TypeScript web UI and a Python API. It monitors imported PEM certificates, issues Let's Encrypt certificates using DNS-01 plugins, renews managed certificates when they are within 30 days of expiration, and deploys the renewed `fullchain.pem` and `privkey.pem`.

## Run it

Requirements: Docker Compose v2, Make, and Python 3.14.8 for generating first-run secrets. The container uses Node 24 to build the UI and Python 3.14.8 to run the API.

```sh
make up
```

On the first run, `make up` creates a private `.env` file and prints the generated admin password. Keep that password and the `APP_ENCRYPTION_KEY` in `.env` backed up: the password is required to sign in, and losing the encryption key makes saved DNS credentials unreadable. Open [http://localhost:8000](http://localhost:8000) and sign in.

```sh
make stop   # stop the container; preserve all data
make start  # start the existing container
make up     # rebuild the image and apply updates
make down   # remove the container and network; preserve ./data and .env
make logs   # follow container logs
```

The web port is bound to `127.0.0.1` by default. Do not expose it directly to the internet; use a secured VPN or an authenticated HTTPS reverse proxy if remote access is needed.
The container runs as a non-root user mapped to the UID/GID that runs `make up`; `make init` creates the default data, certificate, and deployment directories with that owner. If upgrading data created by an earlier root-running image, run `sudo chown -R "$(id -u):$(id -g)" data` once before `make up`.

## Certificates and DNS plugins

* **Import for monitoring:** mount certificate files into `/certificates` (the default host directory is `./data/certificates`), then provide the in-container certificate and optional private-key paths in the UI. Import paths must resolve inside this mounted directory; certificate symlinks are supported when their targets remain inside it. Imported certificates are monitored only; the app does not take over their existing renewal process.
* **Issue and auto-renew:** configure a DNS provider, then request a certificate. Renewal checks run every six hours. The deployment directory defaults to `/deploy` (host directory `./data/deploy`); output filenames are `fullchain.pem` and `privkey.pem`.
* **Use host Let's Encrypt files:** set `CERTIFICATES_HOST_PATH=/etc/letsencrypt` in `.env` to mount the host's full Certbot directory read/write at `/certificates`. The full directory is needed because files under `live/` are symlinks into `archive/`. Use container paths such as `/certificates/live/example.com/fullchain.pem` to import; set an issued certificate's deployment directory to `/certificates/live/example.com` to replace the linked files on renewal while preserving their symlinks.
* **Grant file permissions:** the container runs with the UID/GID of the user who runs `make up`. To permit it to read and update one existing Certbot lineage without changing ownership of all host certificates, grant that UID access to just the lineage's `live` and `archive` directories (requires `acl`): `sudo setfacl -R -m "u:$(id -u):rwX" /etc/letsencrypt/live/example.com /etc/letsencrypt/archive/example.com` and `sudo setfacl -R -d -m "u:$(id -u):rwX" /etc/letsencrypt/live/example.com /etc/letsencrypt/archive/example.com`. These files contain private keys; only grant access to lineages the app should manage. If your host paths differ, set `CERTIFICATES_HOST_PATH` and `DEPLOY_HOST_PATH` in `.env`; they are mounted at `/certificates` and `/deploy`, respectively.
* **DNS plugins:** IONOS and common Certbot DNS plugins are included as presets. For other Certbot DNS plugins, use the custom plugin fields with its PyPI package name and Certbot plugin identifier. The package is installed in the container when issuing or renewing, so it is available again after a container rebuild.

Plugin credentials and options are encrypted with Fernet before being written to SQLite. Certificates, Certbot account state, database, dynamically installed DNS plugins, and deployment data are persisted under `./data`. DNS plugins are third-party code and run inside the container; only install packages you trust.

The initial version focuses on a single local administrator, DNS-01 issuance, monitoring, scheduled/manual renewal, and directory-based deployment. `make down` intentionally does not delete data; remove `./data` and `.env` yourself only when you want to permanently erase the instance and its keys.

## Development and automation

The GitHub Actions CI workflow runs pytest and Vitest coverage reports (without a configured coverage threshold), Ruff, ESLint, Bandit, Pyright, vue-tsc, Playwright browser specs, CodeQL, Trivy, and a container build on pushes to `main`/`master` and pull requests. Publishing a GitHub Release automatically runs the release workflow and publishes versioned and `latest` images to GHCR. GitHub does not trigger workflows when a release is first saved as a draft; to publish its image while it remains a draft, run the **Release** workflow manually from the Actions tab and enter the release tag:

```sh
git tag v1.0.0
git push origin v1.0.0
gh release create v1.0.0 --generate-notes
```

The current frontend toolchain uses Node 24, npm 12.2.1, Vue 3, Vite 8, and TypeScript 6.0.3. The app/test image uses Python 3.14.8.
