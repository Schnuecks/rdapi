# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through
GitHub instead: on the repository page open **Security → Report a vulnerability**. You will
get an answer within a few days, and a fix is released as soon as possible, independent of
the normal release plan.

If that option is not shown, contact the maintainer [@Schnuecks](https://github.com/Schnuecks)
through GitHub and ask for a private channel, without describing the problem publicly.

Helpful details: the RDAPI version (shown in the footer of the web interface), the
RustDesk app version, how the server is exposed (home network, reverse proxy, single
sign-on) and the steps to reproduce.

## Supported versions

Security fixes go into the latest release. Please update to it before reporting
(`docker compose pull && docker compose up -d`).

## Scope

RDAPI is meant to run behind a reverse proxy with HTTPS. The app API (`/api/…`)
has to be reachable for the RustDesk app; the web interface has its own sign-in and can
additionally be put behind a login page of the reverse proxy.

What is in place:

- Passwords hashed with Argon2id; app and web tokens, recovery codes and sign-in steps are
  stored only as SHA-256 hashes.
- Failed sign-ins are limited per address and per username; `X-Forwarded-For` is only
  trusted from local and private networks (`FORWARDED_ALLOW_IPS`).
- Two-factor sign-in (TOTP), passkeys and security keys (WebAuthn) and single sign-on
  (OpenID Connect with PKCE, HTTPS only). With `RDAPI_SECRET_KEY`, the TOTP keys are
  stored encrypted.
- Session cookies are `HttpOnly`, `SameSite=Strict` and, over HTTPS, `__Host-` prefixed;
  every form carries a CSRF token; a Content Security Policy forbids foreign scripts and
  framing; pages are not cached; HSTS is sent over HTTPS.
- Requests without sign-in that create something are limited per address, and request
  bodies are limited in size.
- Security-relevant changes by admins and users are recorded on the “Activity” page.
- Devices are bound to the key they report with; reports with someone else's key are
  ignored.

Known limit: devices report heartbeat, system information and connections **without** a
sign-in, because that is how the RustDesk app works. Anyone who can reach `/api/` can
therefore register made-up devices; this is limited per address and hour, and devices
without an owner are removed after 30 days.
