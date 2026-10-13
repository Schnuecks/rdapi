# RDAPI (früher RustDesk API) – Hinweise für Claude

Schlanker, selbst gebauter API-Server für die RustDesk-App, eine Eigenentwicklung.
Seit 2026-10-06 heißt das Projekt **RDAPI**: Repo `Schnuecks/rdapi` (alte URL leitet weiter), Image
`ghcr.io/schnuecks/rdapi`, Webseite rdapi.app (Quelltext `../rdapi-site`). Lokaler Ordner: `C:\Users\Andreas\Claude\rdapi`.
Python 3.12, FastAPI, SQLite, Jinja2. README und Doku nennen keine anderen Projekte als Vorlage.

## Aufbau

- `rdapi/api.py` – Schnittstelle für den RustDesk-Client (`/api/...`). Tabelle der Endpunkte in
  `docs/en/development.md`.
- `rdapi/web.py` + `rdapi/templates/` – Weboberfläche (Geräte, Verlauf, Adressbuch, Benutzer, Anmeldungen,
  Konto, erste Einrichtung `/setup`).
- `rdapi/security.py` – Argon2-Passwörter, Tokens (nur SHA-256 gespeichert), Fehlversuch-Begrenzung,
  Einrichtungscode.
- `rdapi/db.py` – Schema als Liste `MIGRATIONS` (PRAGMA user_version). Neue Änderungen nur hinten anhängen.
- `rdapi/i18n.py` + `rdapi/locales/{de,fr,es,it,nl}.json` – englische Texte sind die Schlüssel; sechs Sprachen wie in PlateShelf (seit 0.8.0).
- `rdapi/cli.py` – `create-user`, `set-password`, `list-users`, `setup-code`.

## Eigenheiten des RustDesk-Clients (nicht „aufräumen“)

- Ändernde Adressbuch-Aufrufe und Audits gelten nur bei **leerem Body** als erfolgreich.
- Fehler als `{"error": "..."}`; HTTP 401 meldet den Benutzer in der App ab.
- Im Benutzerobjekt muss `info` stehen (der Rust-Teil verlangt das Feld).
- Audits kommen mehrfach; die `nonce` verhindert doppelte Einträge.

## Konventionen

- Sprache: README/Doku primär Englisch (`README.md`, `docs/en/`), Deutsch in `README.de.md` und
  `docs/de/`; das README bleibt kurz, Details stehen in `docs/`. Oberfläche in sechs
  Sprachen; jeder neue sichtbare Text braucht einen Eintrag in allen Dateien in `rdapi/locales/`
  (`tests/test_web.py::test_catalog_is_complete` prüft das für de, fr, es, it, nl). Code-Kommentare dürfen deutsch sein.
- Keine persönlichen Daten (Domains, Namen) im Repo; Beispiele mit `example.com`, `alice`, `bob`.
- Commits mit der GitHub-Noreply-Adresse `27301329+Schnuecks@users.noreply.github.com`
  (private E-Mail wird von GitHub abgelehnt).
- Vor jedem Push: `python -m ruff check`, `python -m ruff format --check`, `python -m pytest -q`.

## Releases

1. CI auf `main` muss grün sein. Neuen Abschnitt in `CHANGELOG.md` (englisch) anlegen.
2. Annotierten Tag setzen und pushen: `git tag -a v0.8.0 -m "RDAPI 0.8.0" && git push origin v0.8.0`
3. Die CI baut `linux/amd64` + `linux/arm64`, veröffentlicht `ghcr.io/schnuecks/rdapi`
   (`latest`, `x.y`, `x.y.z`), prüft mit Trivy und behält die letzten fünf Releases.

Die Version kommt aus dem Tag (Build-Argument `VERSION`) und steht in der Fußzeile.

## Stand und offene Punkte

- Veröffentlicht: `v0.10.2` (Image `ghcr.io/schnuecks/rdapi`), Änderungen in `CHANGELOG.md`. Lizenz AGPL-3.0-or-later.
- Seit 0.9.0 (2026-10-09) **öffentliche Beta in einem frischen Repo** `Schnuecks/rdapi`; das alte heißt `rdapi-beta` (privat, archiviert). Lokal: Zweig `public` folgt `origin/main`, Remote `beta` = altes Repo. Zu jedem Tag ein GitHub-Release mit Notizen (Beta-Hinweis bis 1.0).
- 0.10.0: geteilte Adressbücher (`rdapi/sharing.py`, Tabelle `ab_rules`, Regeln 1/2/3 wie in der App; Admins sehen alle), Gruppen (`user_groups`, `group_members`; Mitglieder sehen in der App die Geräte der anderen), Dateiübertragungen unter `/history/files` (Audit `type` 0 = vom Gerät, 1 = aufs Gerät), Anmeldungen und Aktivität 20 je Seite (`_pager.html`). 0.10.1: Detailseiten einheitlich – links Details, rechts Bearbeiten, Löschen unten im Bearbeiten-Panel; Panel-Einleitungen als `.hint`. Migration 7 baut `address_books` neu auf – `init_db` schaltet dafür Fremdschlüssel aus und prüft danach mit `foreign_key_check`. Unraid-Vorlage `unraid/rdapi.xml`.
- 0.4.0 (2FA mit der echten App am 2026-10-05 bestätigt): Geräte an `uuid` gebunden (nicht „aufräumen“), 2FA (TOTP, App-Ablauf `email_check`/`email_code`),
  tägliche Sicherung (`rdapi/backup.py`), Adressbuch in der Weboberfläche, CSP-Header (Inline-Skript in
  base.html nur per Hash in `main.py` erlaubt: bei Änderung Hash anpassen).
- 0.5.0: Anmeldung über OpenID-Connect-Anbieter (`rdapi/oidc.py`), App-Ablauf `/api/oidc/auth` +
  `/api/oidc/auth-query` (Antwort bis zur Bestätigung exakt „No authed oidc is found“), Bestätigungsseite
  für App-Anmeldungen. Auf dem Server seit 2026-10-05 mit Authelia (Client-ID dort weiter rustdesk-api, Gruppe admins).
- 0.6.0 (Passkeys am 2026-10-06 vom Nutzer am echten Gerät und mit Passwort-Manager-Passkeys bestätigt): Passkeys/FIDO2 nur in der Weboberfläche (`rdapi/passkeys.py`, `static/passkeys.js`); mit Passkey
  braucht die Web-Anmeldung per Passwort einen zweiten Faktor, die App bleibt bei Passwort (+ TOTP).
- 0.7.0: Seite „Aktivität“ (`log_activity` bei jeder sicherheitsrelevanten Änderung mitschreiben!),
  Grenzen je Adresse (public_limiter, report_limiter), BodyLimit 2 MB, optional `RDAPI_SECRET_KEY`
  (TOTP-Schlüssel verschlüsselt, `secretbox.py`; Klartext nur über `totp.secret_of`), `__Host-`-Cookie
  bei HTTPS, OIDC nur https. Menü klappt unter 1080 px zusammen.
- Wiki: nur Spiegel von `docs/` (`tools/wiki_sync.py`, Workflow `wiki.yml` bei Tags v* und von Hand);
  nie direkt im Wiki ändern. `main` und Tags `v*` sind per Ruleset geschützt (PR + Checks test/image,
  Admin-Bypass für Tags).
- Screenshots: `tools/make_screenshots.py` (Playwright), Vorschau: `--serve 8770` (launch.json im
  Elternordner, Eintrag `rdapi-demo`, Anmeldung admin / demo-password-1).
- `CLAUDE.md` liegt nur lokal (in `.gitignore`); README/Doku nennen keine Fremdprodukte wie CrowdSec
  oder andere RustDesk-API-Projekte.
- Seit 2026-10-05 produktiv auf dem Server des Nutzers (Remote-Control-Session „rootserver“): Service
  `api` im selben Compose-Stack wie hbbs/hbbr, Image `:latest`; der alte API-Server ist entfernt.
- Reverse Proxy: uvicorn übernimmt `X-Forwarded-For` nur von `FORWARDED_ALLOW_IPS` (Dockerfile,
  private Netze); nie wieder `*` (`tests/test_proxy.py` prüft das).
