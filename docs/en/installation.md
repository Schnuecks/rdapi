# Installation

**English** · [Deutsch](../de/installation.md) · [← Documentation](README.md)

## Requirements

You need Docker with Docker Compose 2.24 or newer. Images are available for PCs and
servers (amd64) and 64-bit ARM (arm64, e.g. Raspberry Pi 4/5 with a 64-bit OS). Docker
picks the right one automatically.

RDAPI only handles sign-in, address book, devices and history. The connections
themselves still run through your own RustDesk ID and relay server, which you keep as
it is.

## Quick start

```bash
mkdir rdapi && cd rdapi
curl -O https://raw.githubusercontent.com/schnuecks/rdapi/main/compose.yaml
mkdir data && chown 1000:1000 data
docker compose up -d
docker compose logs rdapi
```

The server is now available at `http://<server>:21114`. On the first visit you create
the admin account; the setup code it asks for is in the log (see
[First admin account](#first-admin-account)). Then set up the app as described in
[Usage](usage.md#setting-up-the-app).

The `data` folder must be writable for the user the container runs as (`PUID` and
`PGID`, default 1000). An optional `.env` next to `compose.yaml` takes further settings,
see [Configuration](configuration.md).

## First admin account

As long as there is no user, every page leads to **Create admin account**. The setup
code protects this step: it is printed to the container log on every start and can be
shown again with

```bash
docker compose exec rdapi python -m rdapi.cli setup-code
```

Once the account exists, the setup page is closed and the code is deleted. You add more
users in the web interface under “Users”. For automated deployments,
`RDAPI_ADMIN_USER` and `RDAPI_ADMIN_PASSWORD_FILE` create the first admin on start
instead, see [Configuration](configuration.md#first-admin-without-the-setup-page).

## Behind a reverse proxy

For use over the internet, put the server behind a reverse proxy with HTTPS. The app
cannot pass an additional login page such as Authelia, so the paths need different
protection:

| Path | Purpose | Recommended protection |
|---|---|---|
| `/api/login` | sign-in from the app | IP blocklist, WAF and a rate limit |
| `/api/…` | rest of the app API | IP blocklist and WAF, no login page |
| everything else | web interface | login page (e.g. Authelia) and IP blocklist |

The web interface has its own sign-in with the same credentials as the app, so it stays
protected even if a proxy rule ever fails to apply.

`compose.traefik.yml` is a ready-made stack for Traefik with these three routers:

```bash
mkdir rdapi && cd rdapi
curl -o compose.yml https://raw.githubusercontent.com/schnuecks/rdapi/main/compose.traefik.yml
curl -o .env https://raw.githubusercontent.com/schnuecks/rdapi/main/.env.example
chmod 600 .env                                  # check the values, set DOMAIN
mkdir data && chown 1000:1000 data              # = PUID:PGID from .env
docker compose up -d
docker compose logs rdapi                # shows the setup code
```

Then adjust the **middleware names** in `compose.yml` to your Traefik setup. The routers
have fixed priorities so that `/api/login` wins over `/api/` and `/api/` wins over the
web interface.

The server takes the visitor's real address from the `X-Forwarded-For` header, but only
if the request comes from a local or private network, where the reverse proxy usually
is. From any other address the header is ignored, so nobody can get around the limit on
failed sign-ins with a made-up address. If your proxy is somewhere else, see
[Configuration](configuration.md#reverse-proxy-address).

## Updating

```bash
docker compose pull && docker compose up -d
```

The database is upgraded automatically on startup. What changed in each version is
listed in the [CHANGELOG](../../CHANGELOG.md).

## Data and backups

Everything lives in `data/rdapi.sqlite3`. The server backs it up every day to
`data/backups/` and keeps the last seven backups; admins create, download and restore
backups in the web interface under “Backups” (see [Usage](usage.md#backups)). For a copy
somewhere else, back up the whole `data` folder or download a backup regularly.

History and the sign-in log are deleted after 365 days (`RDAPI_HISTORY_DAYS`).

## Moving from another API server

1. Start RDAPI on a test subdomain next to the old server. If both run on the same
   host, set `COMPOSE_PROJECT_NAME` and `SVC` in `.env` to names the old stack does not
   use.
2. Point the API server of one app to the test address and check: sign-in, address book
   (add an entry, set a tag, rename, delete), the device shows up under “Devices”, a
   connection shows up in the history.
3. If everything works: stop the old server, set the final `DOMAIN` in `.env`, run
   `docker compose up -d` and point all apps to the final address.

Users and address books are **not** imported from the old server; create the users again
and fill the address books in the app.
