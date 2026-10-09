<p align="center"><img src="rdapi/static/logo.svg" width="96" alt="RDAPI"></p>

# RDAPI

**English** · [Deutsch](README.de.md)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white" alt="Python 3.12">
  <a href="https://github.com/Schnuecks/rdapi/pkgs/container/rdapi"><img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker ready"></a>
  <img src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-E4572E" alt="Platform amd64 | arm64">
  <img src="https://img.shields.io/badge/RustDesk_app-1.5-E4572E" alt="RustDesk app 1.5">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-4C9A2A" alt="License AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/status-beta-E4572E" alt="Status: beta">
  <img src="https://img.shields.io/badge/maintained-yes-4C9A2A" alt="Maintained">
</p>

RDAPI is a small, self-hosted API server for the RustDesk app. It adds what a
household or a small team needs on top of your own ID and relay server: signing in to
the app, a personal address book that follows you to every device, a list of your
devices and a history of incoming connections, plus a web interface to manage it all.

> [!IMPORTANT]
> **Public beta.** Everything in RDAPI works, but the official RustDesk ID server (hbbs, up
> to 1.1.16) cannot yet connect a **signed-in** app: connections fail with “Failed to secure
> tcp: deadline has elapsed”. This happens with any API server and is fixed in RustDesk's
> [pull request #706](https://github.com/rustdesk/rustdesk-server/pull/706). Until an ID server release contains the fix, sign-in, address
> book, devices and history work, but to connect, sign out in the app first. Version 1.0
> follows once the fix is released.

![Devices in the web interface](docs/screenshots/devices.png)

## Features

- **Sign-in in the app** with username and password, several users, admins and regular
  users
- **Address book** per user with tags, synchronised between all devices you sign in on and
  editable in the web interface as well
- **Shared address books** for the family or the team, per user or group with read only,
  read and change or full control
- **Device list** with online status, operating system and version; the app shows your
  devices and those of your **groups** under “Accessible devices”
- **Connection history:** who connected to which device, when and for how long, plus the
  files copied during a connection
- **Web interface** for devices, history, address book, users, sign-ins and your account,
  in six languages (English, German, French, Spanish, Italian, Dutch), light and dark theme
- **Two-factor sign-in** with an authenticator app, in the web interface and in the
  RustDesk app, with recovery codes
- **Passkeys and security keys** (FIDO2) in the web interface: sign in without a
  password or use them as second factor
- **Single sign-on** through an OpenID Connect provider such as Authelia, in the web
  interface and in the app; the normal sign-in stays
- **Security:** Argon2id passwords, tokens stored only as hashes, failed sign-ins limited
  per address and per user, devices bound to their own key, sign-in log, container runs
  read-only without root
- **Daily automatic backups**, download and restore in the web interface
- **Small and easy to run:** one container, one SQLite file, images for amd64 and arm64

| Connection history | Address book |
|---|---|
| ![Connection history](docs/screenshots/history.png) | ![Address book with tags](docs/screenshots/address-book.png) |

## Quick start

You need Docker with Docker Compose 2.24 or newer and your own RustDesk ID and relay
server.

```bash
mkdir rdapi && cd rdapi
curl -O https://raw.githubusercontent.com/schnuecks/rdapi/main/compose.yaml
mkdir data && chown 1000:1000 data
docker compose up -d
```

Open `http://<server>:21114` and create the admin account; the setup code is in the log
(`docker compose logs rdapi`). Then enter the address as API server in the app
under *Settings → Network*. To update: `docker compose pull && docker compose up -d`.

For use over the internet, put the server behind a reverse proxy with HTTPS; see
[Installation](docs/en/installation.md).

## Documentation

- [Installation](docs/en/installation.md): quick start, reverse proxy, updating, data and
  backups, moving from another API server
- [Configuration](docs/en/configuration.md): all settings, single sign-on, user accounts,
  command line
- [Usage](docs/en/usage.md): setting up the app, web interface, two-factor sign-in,
  passkeys, backups, troubleshooting
- [Development](docs/en/development.md): running locally, tests, API endpoints,
  translations, releases

What changed in each version is listed in the [CHANGELOG](CHANGELOG.md).

## Support

RDAPI is free and stays free. If it saves you time, you can buy me a coffee; it
keeps the project going. Thank you!

<p>
  <a href="https://buymeacoffee.com/il6hhwtzr6"><img src="https://img.shields.io/badge/Buy_me_a_coffee-10_%E2%82%AC-FFDD00?logo=buymeacoffee&logoColor=black" alt="Buy me a coffee: 10 €"></a>
  <a href="https://buymeacoffee.com/il6hhwtzr6"><img src="https://img.shields.io/badge/Buy_me_a_coffee-25_%E2%82%AC-FFDD00?logo=buymeacoffee&logoColor=black" alt="Buy me a coffee: 25 €"></a>
  <a href="https://buymeacoffee.com/il6hhwtzr6"><img src="https://img.shields.io/badge/Buy_me_a_coffee-50_%E2%82%AC-FFDD00?logo=buymeacoffee&logoColor=black" alt="Buy me a coffee: 50 €"></a>
</p>

## Feedback

Bug reports and ideas are welcome as
[GitHub issues](https://github.com/schnuecks/rdapi/issues). Please report security
problems privately; see [SECURITY](SECURITY.md) and [CONTRIBUTING](CONTRIBUTING.md).

## License

Copyright (C) 2026 Schnuecks

RDAPI is free software under the
[GNU Affero General Public License, version 3 or later](LICENSE) (AGPL-3.0-or-later). You
may use, modify and share it.

If you distribute a modified version or offer it to others over a network, you must make
the source code of your version available to them under the same license. The “Source
code on GitHub” link in the footer does that for this version; for your own version,
point it to your source code (`APP_REPO` in `rdapi/web.py`).

The program is provided without any warranty. See the [license](LICENSE) for details.
The Barlow fonts in `rdapi/static/fonts/` are under the SIL Open Font License (see
`OFL.txt` there); RDAPI serves them itself, so no page loads anything from Google
or other servers. RustDesk is a trademark of its respective owners; this project is not
affiliated with it.
