# Configuration

**English** · [Deutsch](../de/configuration.md) · [← Documentation](README.md)

All settings are optional. With `compose.yaml`, put them into a `.env` next to it; with
`compose.traefik.yml`, add them under `environment:` of the service. Then run
`docker compose up -d`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `RDAPI_DEFAULT_LANGUAGE` | – | `de`, `en`, `fr`, `es`, `it` or `nl`; without it the browser language decides (English if it is none of these) |
| `RDAPI_DEFAULT_THEME` | `system` | `system`, `light` or `dark` |
| `TZ` | `Europe/Berlin` | time zone for times in the web interface |
| `RDAPI_APP_TOKEN_DAYS` | `90` | the app sign-in expires after this many days without use |
| `RDAPI_WEB_SESSION_HOURS` | `12` | a web session expires after this many hours without use |
| `RDAPI_COOKIE_SECURE` | `auto` | `auto` marks the session cookie `Secure` for HTTPS requests, also behind a proxy; `true` or `false` force it |
| `RDAPI_HISTORY_DAYS` | `365` | history and sign-in log are deleted after this many days |
| `RDAPI_ONLINE_SECONDS` | `60` | a device counts as online this long after it last reported |
| `RDAPI_LOGIN_MAX_FAILURES_IP` | `10` | failed sign-ins per address within the window |
| `RDAPI_LOGIN_MAX_FAILURES_USER` | `20` | failed sign-ins per username within the window |
| `RDAPI_LOGIN_WINDOW_SECONDS` | `900` | window for failed sign-ins |
| `RDAPI_UNOWNED_DEVICE_DAYS` | `30` | devices without an owner are removed after this many days without a report; `0` keeps them |
| `RDAPI_NEW_DEVICES_PER_HOUR` | `20` | new devices one address may register per hour |
| `RDAPI_DEVICE_REQUESTS_PER_MINUTE` | `600` | reports (heartbeat, system information, history) one address may send per minute; enough for dozens of devices behind one router |
| `RDAPI_SECRET_KEY_FILE` | – | file with a key that encrypts the two-factor keys, see below (or `RDAPI_SECRET_KEY`) |
| `RDAPI_BACKUP_KEEP` | `7` | number of daily backups to keep; `0` turns daily backups off |
| `RDAPI_BACKUP_DIR` | `/data/backups` | folder for the backups |
| `RDAPI_DB_PATH` | `/data/rdapi.sqlite3` | location of the database |
| `FORWARDED_ALLOW_IPS` | local and private networks | addresses of reverse proxies whose `X-Forwarded-For` is trusted, see below |
| `PUID`, `PGID` | `1000` | user and group the container runs as |
| `PORT` | `21114` | port on the host (`compose.yaml` only) |

## Reverse proxy address

Behind a reverse proxy, every request comes from the proxy. The proxy passes the
visitor's real address in the `X-Forwarded-For` header, and the server uses it for the
limit on failed sign-ins, the sign-in log and the history.

The server only trusts this header from the addresses in `FORWARDED_ALLOW_IPS`. The
default covers local and private networks
(`127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7`), which includes a
reverse proxy in the same Docker network. If you know the proxy's address, you can narrow
it down, e.g. `FORWARDED_ALLOW_IPS=172.20.0.0/16`. If your proxy runs on another host
with a public address, enter exactly that address. Never use `*`: then anyone who
reaches the server directly can pretend to have any address.

## Encrypting two-factor keys

Set `RDAPI_SECRET_KEY_FILE` (or `RDAPI_SECRET_KEY`) to a long random value to store the
keys of two-factor sign-in encrypted (AES-256-GCM). A copy of the database or a downloaded
backup then contains nothing that produces valid codes. On the next start, existing keys
are encrypted automatically.

```bash
openssl rand -base64 48 > secret_key
sudo chown 1000:1000 secret_key && sudo chmod 400 secret_key    # = PUID:PGID
```

The file must belong to the user the container runs as (`PUID:PGID`, default 1000; without
a `user:` line in the compose file, 10001), and nobody else should be able to read it. If
the container cannot read it, it stops on start with “Permission denied”. Keep the file
outside the `data` folder, so it does not end up in the backups, but include it in the
backup of your server.

Keep this value safe and keep it the same: without it, or with a different one, the codes
of all users fail until it is set again (the log says so on start). Users can still sign
in with a recovery code or a passkey, and an admin can turn two-factor sign-in off for
them.

## Single sign-on

Besides username and password, people can sign in through an OpenID Connect provider such
as Authelia, in the web interface and in the RustDesk app. The provider then checks the
password and the second factor. The normal sign-in stays available.

| Variable | Default | Meaning |
|---|---|---|
| `RDAPI_OIDC_ISSUER` | – | address of the provider, e.g. `https://auth.example.com`; turns single sign-on on. Must use `https://` (except `localhost`), otherwise single sign-on stays off |
| `RDAPI_OIDC_CLIENT_ID` | – | client ID registered at the provider |
| `RDAPI_OIDC_CLIENT_SECRET_FILE` | – | file with the client secret, e.g. a Docker secret (or `RDAPI_OIDC_CLIENT_SECRET`) |
| `RDAPI_OIDC_NAME` | `SSO` | name on the button: “Sign in with …” |
| `RDAPI_OIDC_ADMIN_GROUP` | – | members of this group become admins on sign-in |
| `RDAPI_OIDC_CREATE_USERS` | `true` | create an account on the first sign-in; `false` only lets in existing accounts |
| `RDAPI_PUBLIC_URL` | – | public address, if it cannot be taken from the request; also used for passkeys |

At the provider, register a confidential client with the redirect URI
`https://<your address>/oidc/callback`, the scopes `openid profile email groups`, PKCE
with `S256` and the client secret sent in the request body (`client_secret_post`). For
Authelia, the client looks like this:

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: rdapi
        client_name: RDAPI
        client_secret: '$pbkdf2-sha512$...'   # hash of the secret
        authorization_policy: two_factor
        redirect_uris:
          - https://rdapi.example.com/oidc/callback
        scopes: [openid, profile, email, groups]
        require_pkce: true
        pkce_challenge_method: S256
        token_endpoint_auth_method: client_secret_post
```

How accounts are matched:

- After the first sign-in, the account is linked to the person at the provider for good,
  even if their name changes there.
- Before that, an existing account with the same username, or with the same email address
  if the provider confirms it, is linked.
- Otherwise a new account is created (unless `RDAPI_OIDC_CREATE_USERS=false`). It has no
  password anyone knows; an admin can set one under “Users”.
- Members of `RDAPI_OIDC_ADMIN_GROUP` become admins. Admin rights are never taken away
  automatically, so nobody locks themselves out; remove them under “Users”.
- Disabled accounts cannot sign in this way either. Two-factor sign-in in RDAPI is
  skipped for this way, because the provider takes care of it.

## User accounts

There are two roles: **admins** manage users and see all devices and connections;
**users** see their own devices, history and address book. Admins create users, set new
passwords and disable accounts under “Users” in the web interface.

Setting a new password or disabling a user ends all of their sessions, in the web
interface and in the app. Everyone can change their own password, set up two-factor
sign-in and end single sessions under “Account”; see
[Two-factor sign-in](usage.md#two-factor-sign-in).

## Command line

The same tasks are also available on the command line:

```bash
docker compose exec rdapi python -m rdapi.cli create-user alice           # add --admin for an admin
docker compose exec rdapi python -m rdapi.cli set-password alice          # also ends all sessions
docker compose exec rdapi python -m rdapi.cli list-users
docker compose exec rdapi python -m rdapi.cli reset-2fa alice             # turns off two-factor sign-in
docker compose exec rdapi python -m rdapi.cli setup-code                  # only before the first account
```

## First admin without the setup page

For automated deployments the first admin can be created on start instead of on the
setup page:

| Variable | Meaning |
|---|---|
| `RDAPI_ADMIN_USER` | username of the first admin |
| `RDAPI_ADMIN_PASSWORD_FILE` | file with the password, e.g. a Docker secret |
| `RDAPI_ADMIN_PASSWORD` | the password directly (only if no file is possible) |

The account is only created if there is no user yet; later changes to these variables
have no effect.
