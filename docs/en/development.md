# Development

**English** · [Deutsch](../de/development.md) · [← Documentation](README.md)

## Running locally

You need Python 3.12.

```bash
pip install -r requirements-dev.txt
RDAPI_DB_PATH=./data/dev.sqlite3 \
  RDAPI_ADMIN_USER=admin RDAPI_ADMIN_PASSWORD=admin-password \
  uvicorn --factory rdapi.main:create_app --port 21114 --reload
```

The web interface is then at `http://localhost:21114`.

## Structure

| Path | Purpose |
|---|---|
| `rdapi/api.py` | API for the RustDesk app (`/api/…`) |
| `rdapi/web.py`, `rdapi/templates/` | web interface |
| `rdapi/security.py` | passwords, tokens, limits, setup code, recovery codes |
| `rdapi/totp.py` | codes for two-factor sign-in (RFC 6238) |
| `rdapi/backup.py` | daily backups and restoring |
| `rdapi/oidc.py` | single sign-on through an OpenID Connect provider |
| `rdapi/passkeys.py`, `rdapi/static/passkeys.js` | passkeys and security keys (WebAuthn) |
| `rdapi/db.py` | database schema as a list of migrations; only append new ones |
| `rdapi/i18n.py`, `rdapi/locales/` | translations |
| `rdapi/cli.py` | command line |

## Tests

```bash
python -m pytest -q
python -m ruff check
python -m ruff format --check
```

`tests/test_api.py` replays the requests of the RustDesk app, `tests/test_web.py` covers
the web interface, `tests/test_security.py` device reports, limits and security headers,
`tests/test_twofactor.py` two-factor sign-in, `tests/test_oidc.py` single sign-on with a
simulated provider, `tests/test_passkeys.py` passkeys with a simulated authenticator, `tests/test_backup_and_ab.py` backups and
the address book in the web interface, and `tests/test_proxy.py` the handling of
`X-Forwarded-For`.

## Screenshots

```bash
pip install playwright && python -m playwright install chromium
python tools/make_screenshots.py
```

This creates a demo database with made-up devices and connections and saves the pictures
to `docs/screenshots/`. `python tools/make_screenshots.py --serve 8770` only starts the
server with the demo data (sign-in: `admin` / `demo-password-1`).

## API endpoints

| Feature | Endpoints |
|---|---|
| Sign-in | `POST /api/login` (also the second step with `type: email_code`), `/api/logout`, `/api/currentUser`, `GET /api/login-options` |
| Single sign-on | `POST /api/oidc/auth`, `GET /api/oidc/auth-query` |
| Address book | `/api/ab/settings`, `/api/ab/personal`, `/api/ab/shared/profiles`, `/api/ab/peers`, `/api/ab/tags/{guid}`, `/api/ab/peer/add\|update/{guid}`, `DELETE /api/ab/peer/{guid}`, `/api/ab/tag/add\|rename\|update/{guid}`, `DELETE /api/ab/tag/{guid}`, legacy format: `GET/POST /api/ab` |
| Device list | `GET /api/users`, `/api/peers`, `/api/device-group/accessible` |
| Devices | `POST /api/heartbeat`, `/api/sysinfo`, `/api/sysinfo_ver` |
| History | `POST /api/audit/conn`, `/api/audit/file`, `/api/audit/alarm` |

What the app expects, and what must therefore stay as it is:

- Address book changes and audits only count as successful with an **empty body**.
- Errors are returned as `{"error": "…"}`; HTTP 401 signs the user out of the app.
- The user object must contain an `info` field.
- Audits are sent again on failure; the `nonce` sent along prevents duplicate entries.
- Heartbeat, sysinfo and audits carry the device's `uuid`; the server binds a device to the
  first one it sees and ignores reports with another one.
- Two-factor sign-in: the first `/api/login` answers `{"type": "email_check", "tfa_type":
  "tfa_check", "secret": …}`; the app then sends `type: email_code` with `secret` and the
  code in `tfaCode`.
- Single sign-on: `/api/login-options` lists `oidc/<name>`; `/api/oidc/auth` answers
  `{"code", "url"}`, the app opens the URL and polls `/api/oidc/auth-query` every second
  for three minutes. Until the sign-in is confirmed, the answer must be exactly
  `{"error": "No authed oidc is found"}`, otherwise the app stops asking.

## Translations

The web interface speaks German, English, French, Spanish, Italian and Dutch. The English
texts in the code are the keys; `rdapi/locales/<code>.json` (`de`, `fr`, `es`, `it`, `nl`)
maps them to the other languages. Every new visible text needs an entry in each of these
files with the same `{placeholders}`, otherwise `tests/test_web.py::test_catalog_is_complete`
fails. Another language needs a `rdapi/locales/<code>.json` and entries in `LANGUAGES` and
`DATE_FORMAT` in `rdapi/i18n.py`.

## Releases

Pushes and pull requests run lint, tests and a trial image build for amd64 and arm64.
A version tag publishes the image to the GitHub Container Registry:

```bash
git tag -a v0.3.2 -m "RDAPI 0.3.2" && git push origin v0.3.2
```

The image gets the tags `latest`, `0.3` and `0.3.2` and is scanned with Trivy; images
older than the last five releases are deleted automatically. The tag becomes the version
in the footer of the web interface. Add the changes to the [CHANGELOG](../../CHANGELOG.md)
before tagging. Dependabot proposes updates for Python packages, GitHub Actions and the
base image every Monday.

## Wiki

The GitHub wiki shows this documentation, but it is only a copy: on every release, and
when started by hand under “Actions” → “Wiki”, `tools/wiki_sync.py` copies `docs/en` and
`docs/de` into the wiki and rewrites the links. Change the documentation here in `docs/`;
edits in the wiki are overwritten.
