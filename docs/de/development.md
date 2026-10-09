# Entwicklung

[English](../en/development.md) · **Deutsch** · [← Dokumentation](README.md)

## Lokal starten

Du brauchst Python 3.12.

```bash
pip install -r requirements-dev.txt
RDAPI_DB_PATH=./data/dev.sqlite3 \
  RDAPI_ADMIN_USER=admin RDAPI_ADMIN_PASSWORD=admin-password \
  uvicorn --factory rdapi.main:create_app --port 21114 --reload
```

Die Weboberfläche ist dann unter `http://localhost:21114` erreichbar.

## Aufbau

| Pfad | Zweck |
|---|---|
| `rdapi/api.py` | Schnittstelle für die RustDesk-App (`/api/…`) |
| `rdapi/web.py`, `rdapi/templates/` | Weboberfläche |
| `rdapi/security.py` | Passwörter, Tokens, Begrenzungen, Einrichtungscode, Wiederherstellungscodes |
| `rdapi/totp.py` | Codes für die Zwei-Faktor-Anmeldung (RFC 6238) |
| `rdapi/backup.py` | tägliche Sicherung und Zurückspielen |
| `rdapi/oidc.py` | Anmeldung über einen OpenID-Connect-Anbieter |
| `rdapi/passkeys.py`, `rdapi/static/passkeys.js` | Passkeys und Sicherheitsschlüssel (WebAuthn) |
| `rdapi/db.py` | Datenbankschema als Liste von Migrationen; neue nur hinten anhängen |
| `rdapi/i18n.py`, `rdapi/locales/` | Übersetzungen |
| `rdapi/cli.py` | Kommandozeile |

## Tests

```bash
python -m pytest -q
python -m ruff check
python -m ruff format --check
```

`tests/test_api.py` spielt die Anfragen der RustDesk-App nach, `tests/test_web.py` prüft
die Weboberfläche, `tests/test_security.py` Gerätemeldungen, Begrenzungen und
Sicherheits-Header, `tests/test_twofactor.py` die Zwei-Faktor-Anmeldung, `tests/test_oidc.py` die Anmeldung
über einen nachgestellten Anbieter, `tests/test_passkeys.py` Passkeys mit einem
nachgestellten Authenticator,
`tests/test_backup_and_ab.py` Sicherungen und das Adressbuch in der Weboberfläche und
`tests/test_proxy.py` den Umgang mit `X-Forwarded-For`.

## Screenshots

```bash
pip install playwright && python -m playwright install chromium
python tools/make_screenshots.py
```

Das legt eine Demo-Datenbank mit erfundenen Geräten und Verbindungen an und speichert die
Bilder in `docs/screenshots/`. `python tools/make_screenshots.py --serve 8770` startet nur
den Server mit den Demo-Daten (Anmeldung: `admin` / `demo-password-1`).

## API-Endpunkte

| Funktion | Endpunkte |
|---|---|
| Anmeldung | `POST /api/login` (auch der zweite Schritt mit `type: email_code`), `/api/logout`, `/api/currentUser`, `GET /api/login-options` |
| Anmeldung über Anbieter | `POST /api/oidc/auth`, `GET /api/oidc/auth-query` |
| Adressbuch | `/api/ab/settings`, `/api/ab/personal`, `/api/ab/shared/profiles`, `/api/ab/peers`, `/api/ab/tags/{guid}`, `/api/ab/peer/add\|update/{guid}`, `DELETE /api/ab/peer/{guid}`, `/api/ab/tag/add\|rename\|update/{guid}`, `DELETE /api/ab/tag/{guid}`, altes Format: `GET/POST /api/ab` |
| Geräteliste | `GET /api/users`, `/api/peers`, `/api/device-group/accessible` |
| Geräte | `POST /api/heartbeat`, `/api/sysinfo`, `/api/sysinfo_ver` |
| Verlauf | `POST /api/audit/conn`, `/api/audit/file`, `/api/audit/alarm` |

Was die App erwartet und deshalb so bleiben muss:

- Adressbuch-Änderungen und Audits gelten nur mit **leerem Body** als erfolgreich.
- Fehler kommen als `{"error": "…"}`; HTTP 401 meldet den Benutzer in der App ab.
- Im Benutzerobjekt muss ein Feld `info` stehen.
- Audits werden bei Fehlern erneut gesendet; die mitgeschickte `nonce` verhindert doppelte
  Einträge.
- Heartbeat, Sysinfo und Audits enthalten die `uuid` des Geräts; der Server bindet ein
  Gerät an die erste, die er sieht, und ignoriert Meldungen mit einer anderen.
- Zwei-Faktor-Anmeldung: Der erste `/api/login` antwortet `{"type": "email_check",
  "tfa_type": "tfa_check", "secret": …}`; die App schickt dann `type: email_code` mit
  `secret` und dem Code in `tfaCode`.
- Anmeldung über Anbieter: `/api/login-options` nennt `oidc/<Name>`; `/api/oidc/auth`
  antwortet `{"code", "url"}`, die App öffnet die Adresse und fragt drei Minuten lang jede
  Sekunde `/api/oidc/auth-query` ab. Bis die Anmeldung bestätigt ist, muss die Antwort genau
  `{"error": "No authed oidc is found"}` lauten, sonst hört die App auf zu fragen.

## Übersetzungen

Die Weboberfläche spricht Deutsch, Englisch, Französisch, Spanisch, Italienisch und
Niederländisch. Die englischen Texte im Code sind die Schlüssel; `rdapi/locales/<code>.json`
(`de`, `fr`, `es`, `it`, `nl`) ordnet ihnen die anderen Sprachen zu. Jeder neue sichtbare
Text braucht in jeder dieser Dateien einen Eintrag mit denselben `{Platzhaltern}`, sonst
schlägt `tests/test_web.py::test_catalog_is_complete` fehl. Eine weitere Sprache braucht eine
`rdapi/locales/<code>.json` und Einträge in `LANGUAGES` und `DATE_FORMAT` in `rdapi/i18n.py`.

## Releases

Pushes und Pull Requests führen Lint, Tests und einen Probe-Build des Images für amd64
und arm64 aus. Ein Versions-Tag veröffentlicht das Image in der GitHub Container Registry:

```bash
git tag -a v0.3.2 -m "RDAPI 0.3.2" && git push origin v0.3.2
```

Das Image bekommt die Tags `latest`, `0.3` und `0.3.2` und wird mit Trivy geprüft; Images
älter als die letzten fünf Releases werden automatisch gelöscht. Der Tag wird zur Version
in der Fußzeile der Weboberfläche. Vor dem Tag die Änderungen im
[CHANGELOG](../../CHANGELOG.md) eintragen. Dependabot schlägt jeden Montag Updates für
Python-Pakete, GitHub Actions und das Basis-Image vor.

## Wiki

Das GitHub-Wiki zeigt diese Doku, ist aber nur eine Kopie: Bei jedem Release, und von Hand
unter „Actions“ → „Wiki“, kopiert `tools/wiki_sync.py` `docs/en` und `docs/de` ins Wiki
und schreibt die Links um. Geändert wird die Doku hier in `docs/`; Änderungen im Wiki
werden überschrieben.
