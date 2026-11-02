# LetsRenew

LetsRenew is a single-container certificate manager with a Vue/TypeScript web UI and a Python API. It monitors imported PEM certificates, issues Let's Encrypt certificates using DNS-01 plugins, renews managed certificates when they are within 30 days of expiration, and deploys the renewed `fullchain.pem` and `privkey.pem`.

## Run it

Requirements: Docker Compose v2, Make, and Python 3 for generating first-run secrets.

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

## Certificates and DNS plugins

* **Import for monitoring:** mount certificate files into `/certificates` (the default host directory is `./data/certificates`), then provide the in-container PEM path in the UI. Imported certificates are monitored only; the app does not take over their existing renewal process.
* **Issue and auto-renew:** configure a DNS provider, then request a certificate. Renewal checks run every six hours. The deployment directory defaults to `/deploy` (host directory `./data/deploy`); output filenames are `fullchain.pem` and `privkey.pem`.
* **Mount other paths:** set `CERTIFICATES_HOST_PATH` and/or `DEPLOY_HOST_PATH` in `.env` before running Compose to mount other host directories at `/certificates` and `/deploy`. Update the paths used in the UI accordingly.
* **DNS plugins:** IONOS and common Certbot DNS plugins are included as presets. For other Certbot DNS plugins, use the custom plugin fields with its PyPI package name and Certbot plugin identifier. The package is installed in the container when issuing or renewing, so it is available again after a container rebuild.

Plugin credentials and options are encrypted with Fernet before being written to SQLite. Certificates, Certbot account state, database, and deployment data are persisted under `./data`. DNS plugins are third-party code and run inside the container; only install packages you trust.

The initial version focuses on a single local administrator, DNS-01 issuance, monitoring, scheduled/manual renewal, and directory-based deployment. `make down` intentionally does not delete data; remove `./data` and `.env` yourself only when you want to permanently erase the instance and its keys.

## Development and automation

The GitHub Actions CI workflow runs backend tests, builds the Vue frontend, and builds the container on pushes to `main`/`master` and pull requests. Pushing a `v*` tag runs the release workflow, publishes versioned and `latest` images to GHCR, and creates a GitHub Release:

```sh
git tag v1.0.0
git push origin v1.0.0
```
