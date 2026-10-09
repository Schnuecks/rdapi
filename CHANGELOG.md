# Changelog

## 0.9.0

- **First public release (beta).** RDAPI is now open source on GitHub. Signed-in apps
  cannot connect through the official RustDesk ID server up to 1.1.16 yet; the README and
  the troubleshooting section explain the workaround until RustDesk releases the fix.
  Version 1.0 follows once it is out.

## 0.8.0

- **Six languages:** the web interface is now also available in French, Spanish, Italian
  and Dutch, besides English and German. The language follows the browser or the choice in
  the language menu; `RDAPI_DEFAULT_LANGUAGE` accepts `de`, `en`, `fr`, `es`, `it` and `nl`.
  Dates and times use the usual format of each language.

## 0.7.5

- **New name: RDAPI.** RustDesk API is now called RDAPI: repository
  `github.com/Schnuecks/rdapi`, image `ghcr.io/schnuecks/rdapi`, service `rdapi` in the
  compose templates. Settings (`RDAPI_…`) and data stay as they are.

## 0.7.1

- **Fix: signing out (and other buttons) sometimes did nothing.** Behind a reverse proxy
  with a login page such as Authelia, the proxy redirects a form to its login page once
  its own session has expired. The Content Security Policy from 0.4.0 only allowed forms
  to end up on RustDesk API itself, so the browser silently blocked the whole click. Forms
  may now also be redirected to HTTPS addresses.
- After signing in at the proxy, the browser comes back to the address of the form. For
  signing out, `/logout` now shows a page with a “Sign out” button instead of an error;
  other form-only addresses lead to the start page.

## 0.7.0

- **Activity log:** a new admin page “Activity” records who changed users (created,
  password set, admin rights, disabled, deleted, two-factor reset), devices (owner,
  removed), backups (created, downloaded, uploaded, restored) or their own sign-in
  (password, two-factor sign-in, recovery codes, passkeys), and when, with the address.
- **Limits against flooding:** starting a passkey or single sign-on sign-in is limited
  per address, device reports per address and minute (`RDAPI_DEVICE_REQUESTS_PER_MINUTE`,
  default 600), and requests larger than 2 MB are rejected (except uploading a backup).
  Blocked sign-in attempts are logged at most once a minute per address.
- **Encrypted two-factor keys:** with `RDAPI_SECRET_KEY_FILE` (or `RDAPI_SECRET_KEY`), the
  keys of two-factor sign-in are stored encrypted, so a copy of the database or a backup
  no longer contains them; existing keys are encrypted on start. Optional; without the
  setting nothing changes.
- **Browser rules:** pages and API answers are not cached, HSTS is sent over HTTPS, and
  over HTTPS the session cookie gets the `__Host-` prefix (everyone signs in once more
  after the update).
- **Single sign-on only over HTTPS:** an `http://` provider address (except `localhost`)
  turns single sign-on off with a message in the log.
- The menu collapses on narrower windows, so the extra menu entry fits.

## 0.6.0

- **Passkeys and security keys (FIDO2/WebAuthn) in the web interface,** for a safe web
  interface without an extra sign-in service:
  - under “Account”, add passkeys (fingerprint, face or PIN of a device) or security keys
    and remove them again
  - **sign in without a password** with “Sign in with a passkey”
  - **as second factor:** once a user has a passkey, the password alone is no longer
    enough in the web interface; the passkey, the code from the authenticator app or a
    recovery code is asked for
  - recovery codes come with the first passkey
  - admins remove passkeys under “Users” → “Turn off two-factor sign-in”, as does
    `rdapi.cli reset-2fa`
- The RustDesk app cannot use passkeys and keeps signing in as before.
- New dependency `webauthn` for checking passkeys.

## 0.5.0

- **Single sign-on:** sign in through an OpenID Connect provider such as Authelia, in the
  web interface (“Sign in with …” on the sign-in page) and in the RustDesk app (“Login
  with …”). The provider checks password and second factor; RustDesk API links the person
  to an existing account by username or confirmed email address, or creates one. Members
  of an admin group become admins. Sign-ins from the app are confirmed once in the
  browser. Set up with `RDAPI_OIDC_ISSUER`, `RDAPI_OIDC_CLIENT_ID` and
  `RDAPI_OIDC_CLIENT_SECRET_FILE`; see the configuration guide. The normal sign-in stays.

## 0.4.0

- **Two-factor sign-in:** under “Account”, everyone can turn on codes from an
  authenticator app. The web interface and the RustDesk app then ask for a code after the
  password; eight recovery codes help if the phone is lost. Admins can turn it off for a
  user under “Users” or with `python -m rdapi.cli reset-2fa`.
- **Address book in the web interface:** add, edit and remove entries and manage tags with
  their colours. Fields only the app knows, such as saved passwords, are kept.
- **Daily automatic backups** to `data/backups` (the last seven are kept). Under
  “Backups”, admins back up on demand, download, upload and restore; before restoring, the
  current state is backed up.
- **Devices bound to their key:** besides its RustDesk ID, every device sends an internal
  key. Once known, reports with the same ID but another key no longer change the device,
  its details or its history. Signing in with someone else's device ID no longer takes
  over that device.
- **Fewer made-up devices:** one address may register at most 20 new devices per hour,
  history is only accepted from known devices, and devices without an owner are removed
  after 30 days without a report.
- **No lock-out from outside:** after too many failed sign-ins for a username, addresses
  from which that user has signed in before are still let through, so nobody can lock you
  out by guessing your password. The limit per address stays.
- **Security headers:** the web interface sets a Content Security Policy and forbids being
  shown inside other pages.
- Screenshots in README and documentation.

## 0.3.2

- **Visitor address only trusted from the reverse proxy:** the server now takes the real
  address from `X-Forwarded-For` only for requests from local and private networks, where
  the reverse proxy usually runs (`FORWARDED_ALLOW_IPS`). Before, anyone reaching the
  server directly could send a made-up address and get around the limit on failed
  sign-ins per address. If your reverse proxy has a public address, set
  `FORWARDED_ALLOW_IPS` to it.
- **License:** RustDesk API is now free software under the GNU Affero General Public
  License, version 3 or later (AGPL-3.0-or-later).
- **New documentation:** a short README and detailed guides in `docs/en` and `docs/de`
  (installation, configuration, usage with troubleshooting, development).
- `compose.traefik.yml` names the IP blocklist middleware neutrally `ipblock@file`; as
  before, adjust the middleware names to your Traefik setup.

## 0.3.1

- **Admin account in the first setup:** as long as there is no user, every page leads to the
  setup page (“Create admin account”). It is protected by a setup code that is printed to the
  container log on every start and shown by `python -m rdapi.cli setup-code`; failed attempts
  are rate limited. Once the account exists, the setup page is closed and the code deleted.
  `RDAPI_ADMIN_USER` / `RDAPI_ADMIN_PASSWORD(_FILE)` remain as an optional alternative for
  automated deployments, so `compose.traefik.yml` and `.env.example` no longer need an admin
  secret.

## 0.3.0

First published version.

- **Lean API server for the RustDesk app:** sign-in, personal address book (new and legacy
  format), heartbeat/sysinfo, device list and connection history.
- **Web UI in English and German** with language menu and light/dark mode; user management,
  devices, history, address book, sign-ins and account page.
- **Logo** for favicon, header and login page.
- **Multi-arch image** for `linux/amd64` and `linux/arm64` on
  `ghcr.io/schnuecks/rustdesk-api` (`latest`, `x.y`, `x.y.z`), scanned with Trivy;
  `compose.yaml` for a minimal setup and `compose.traefik.yml` for a stack behind Traefik.
- The session cookie is marked Secure automatically for HTTPS requests, so plain HTTP setups
  can sign in.
