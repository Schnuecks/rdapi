# Konfiguration

[English](../en/configuration.md) · **Deutsch** · [← Dokumentation](README.md)

Alle Einstellungen sind optional. Bei `compose.yaml` kommen sie in eine `.env` daneben,
bei `compose.traefik.yml` unter `environment:` des Dienstes. Danach
`docker compose up -d` ausführen.

## Einstellungen

| Variable | Standard | Bedeutung |
|---|---|---|
| `RDAPI_DEFAULT_LANGUAGE` | – | `de`, `en`, `fr`, `es`, `it` oder `nl`; ohne Angabe entscheidet die Browsersprache (Englisch, wenn es keine davon ist) |
| `RDAPI_DEFAULT_THEME` | `system` | `system`, `light` oder `dark` |
| `TZ` | `Europe/Berlin` | Zeitzone für Zeitangaben in der Weboberfläche |
| `RDAPI_APP_TOKEN_DAYS` | `90` | Anmeldung in der App läuft nach so vielen Tagen ohne Nutzung ab |
| `RDAPI_WEB_SESSION_HOURS` | `12` | Sitzung in der Weboberfläche läuft nach so vielen Stunden ohne Nutzung ab |
| `RDAPI_COOKIE_SECURE` | `auto` | `auto` markiert das Sitzungs-Cookie bei HTTPS-Anfragen als `Secure`, auch hinter einem Proxy; `true` oder `false` erzwingen es |
| `RDAPI_HISTORY_DAYS` | `365` | Verlauf und Anmeldeprotokoll werden nach so vielen Tagen gelöscht |
| `RDAPI_ONLINE_SECONDS` | `60` | so lange nach der letzten Meldung gilt ein Gerät als online |
| `RDAPI_LOGIN_MAX_FAILURES_IP` | `10` | Fehlversuche je Adresse im Zeitfenster |
| `RDAPI_LOGIN_MAX_FAILURES_USER` | `20` | Fehlversuche je Benutzername im Zeitfenster |
| `RDAPI_LOGIN_WINDOW_SECONDS` | `900` | Zeitfenster für Fehlversuche |
| `RDAPI_UNOWNED_DEVICE_DAYS` | `30` | Geräte ohne Besitzer werden nach so vielen Tagen ohne Meldung entfernt; `0` behält sie |
| `RDAPI_NEW_DEVICES_PER_HOUR` | `20` | neue Geräte, die eine Adresse je Stunde anlegen darf |
| `RDAPI_DEVICE_REQUESTS_PER_MINUTE` | `600` | Meldungen (Heartbeat, Systeminfos, Verlauf), die eine Adresse je Minute senden darf; reicht für Dutzende Geräte hinter einem Router |
| `RDAPI_SECRET_KEY_FILE` | – | Datei mit einem Schlüssel, der die Schlüssel der Zwei-Faktor-Anmeldung verschlüsselt, siehe unten (oder `RDAPI_SECRET_KEY`) |
| `RDAPI_BACKUP_KEEP` | `7` | Anzahl der täglichen Sicherungen, die erhalten bleiben; `0` schaltet sie ab |
| `RDAPI_BACKUP_DIR` | `/data/backups` | Ordner für die Sicherungen |
| `RDAPI_DB_PATH` | `/data/rdapi.sqlite3` | Ort der Datenbank |
| `FORWARDED_ALLOW_IPS` | lokale und private Netze | Adressen von Reverse Proxys, deren `X-Forwarded-For` vertraut wird, siehe unten |
| `PUID`, `PGID` | `1000` | Benutzer und Gruppe, unter denen der Container läuft |
| `PORT` | `21114` | Port auf dem Host (nur `compose.yaml`) |

## Adresse des Reverse Proxys

Hinter einem Reverse Proxy kommt jede Anfrage vom Proxy. Der Proxy gibt die echte
Adresse des Besuchers im Header `X-Forwarded-For` weiter, und der Server nutzt sie für
die Begrenzung der Fehlversuche, das Anmeldeprotokoll und den Verlauf.

Der Server vertraut diesem Header nur von den Adressen in `FORWARDED_ALLOW_IPS`. Der
Standard umfasst lokale und private Netze
(`127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7`), also auch einen
Reverse Proxy im selben Docker-Netz. Kennst du die Adresse deines Proxys, kannst du es
enger fassen, z. B. `FORWARDED_ALLOW_IPS=172.20.0.0/16`. Läuft der Proxy auf einem
anderen Rechner mit öffentlicher Adresse, trag genau diese Adresse ein. Nie `*`
verwenden: Dann kann jeder, der den Server direkt erreicht, eine beliebige Adresse
vortäuschen.

## Schlüssel der Zwei-Faktor-Anmeldung verschlüsseln

Setzt du `RDAPI_SECRET_KEY_FILE` (oder `RDAPI_SECRET_KEY`) auf einen langen Zufallswert,
werden die Schlüssel der Zwei-Faktor-Anmeldung verschlüsselt gespeichert (AES-256-GCM).
Eine Kopie der Datenbank oder eine heruntergeladene Sicherung enthält dann nichts, womit
sich gültige Codes erzeugen lassen. Beim nächsten Start werden vorhandene Schlüssel
automatisch verschlüsselt.

```bash
openssl rand -base64 48 > secret_key
sudo chown 1000:1000 secret_key && sudo chmod 400 secret_key    # = PUID:PGID
```

Die Datei muss dem Benutzer gehören, unter dem der Container läuft (`PUID:PGID`, Standard
1000; ohne Zeile `user:` in der Compose-Datei 10001), und sonst niemand sollte sie lesen
können. Kann der Container sie nicht lesen, bricht er beim Start mit „Permission denied“
ab. Leg die Datei außerhalb des Ordners `data` ab, damit sie nicht in den Sicherungen
landet, nimm sie aber in die Sicherung deines Servers auf.

Bewahre den Wert gut auf und ändere ihn nicht: Ohne ihn, oder mit einem anderen, schlagen
die Codes aller Benutzer fehl, bis er wieder gesetzt ist (das Log meldet es beim Start).
Anmelden geht dann noch mit einem Wiederherstellungscode oder einem Passkey, und ein Admin
kann die Zwei-Faktor-Anmeldung für sie ausschalten.

## Anmeldung über einen Anbieter

Neben Benutzername und Passwort kann man sich über einen OpenID-Connect-Anbieter wie
Authelia anmelden, in der Weboberfläche und in der RustDesk-App. Passwort und zweiten
Faktor prüft dann der Anbieter. Die normale Anmeldung bleibt erhalten.

| Variable | Standard | Bedeutung |
|---|---|---|
| `RDAPI_OIDC_ISSUER` | – | Adresse des Anbieters, z. B. `https://auth.example.com`; schaltet die Anmeldung über den Anbieter ein. Muss mit `https://` beginnen (außer `localhost`), sonst bleibt sie aus |
| `RDAPI_OIDC_CLIENT_ID` | – | Client-ID, die beim Anbieter eingetragen ist |
| `RDAPI_OIDC_CLIENT_SECRET_FILE` | – | Datei mit dem Client-Geheimnis, z. B. ein Docker-Secret (oder `RDAPI_OIDC_CLIENT_SECRET`) |
| `RDAPI_OIDC_NAME` | `SSO` | Name auf dem Knopf: „Mit … anmelden“ |
| `RDAPI_OIDC_ADMIN_GROUP` | – | Mitglieder dieser Gruppe werden bei der Anmeldung Admins |
| `RDAPI_OIDC_CREATE_USERS` | `true` | bei der ersten Anmeldung ein Konto anlegen; `false` lässt nur bestehende Konten herein |
| `RDAPI_PUBLIC_URL` | – | öffentliche Adresse, falls sie sich nicht aus der Anfrage ergibt; gilt auch für Passkeys |

Beim Anbieter trägst du einen vertraulichen Client ein, mit der Rücksprung-Adresse
`https://<deine Adresse>/oidc/callback`, den Scopes `openid profile email groups`, PKCE mit
`S256` und dem Client-Geheimnis im Rumpf der Anfrage (`client_secret_post`). Bei Authelia
sieht der Client so aus:

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: rdapi
        client_name: RDAPI
        client_secret: '$pbkdf2-sha512$...'   # Hash des Geheimnisses
        authorization_policy: two_factor
        redirect_uris:
          - https://rdapi.example.com/oidc/callback
        scopes: [openid, profile, email, groups]
        require_pkce: true
        pkce_challenge_method: S256
        token_endpoint_auth_method: client_secret_post
```

So werden Konten zugeordnet:

- Nach der ersten Anmeldung ist das Konto dauerhaft mit der Person beim Anbieter
  verknüpft, auch wenn sich ihr Name dort ändert.
- Vorher wird ein bestehendes Konto mit gleichem Benutzernamen verknüpft, oder mit gleicher
  E-Mail-Adresse, wenn der Anbieter sie bestätigt.
- Sonst wird ein neues Konto angelegt (außer bei `RDAPI_OIDC_CREATE_USERS=false`). Es hat
  kein Passwort, das jemand kennt; ein Admin kann unter „Benutzer“ eins setzen.
- Mitglieder von `RDAPI_OIDC_ADMIN_GROUP` werden Admins. Admin-Rechte werden nie
  automatisch entzogen, damit sich niemand aussperrt; das geht unter „Benutzer“.
- Gesperrte Konten kommen auch so nicht herein. Die Zwei-Faktor-Anmeldung von RDAPI
  entfällt auf diesem Weg, weil der Anbieter sich darum kümmert.

## Benutzerkonten

Es gibt zwei Rollen: **Admins** verwalten die Benutzer und sehen alle Geräte und
Verbindungen; **Benutzer** sehen ihre eigenen Geräte, ihren Verlauf und ihr Adressbuch.
Admins legen Benutzer unter „Benutzer“ in der Weboberfläche an, setzen neue Passwörter und
sperren Konten.

Ein neues Passwort oder eine Sperre beendet alle Sitzungen des Benutzers, in der
Weboberfläche und in der App. Jeder kann unter „Konto“ sein eigenes Passwort ändern, die
Zwei-Faktor-Anmeldung einrichten und einzelne Sitzungen beenden; siehe
[Zwei-Faktor-Anmeldung](usage.md#zwei-faktor-anmeldung).

## Kommandozeile

Dieselben Aufgaben gehen auch auf der Kommandozeile:

```bash
docker compose exec rdapi python -m rdapi.cli create-user alice           # mit --admin für einen Admin
docker compose exec rdapi python -m rdapi.cli set-password alice          # beendet auch alle Sitzungen
docker compose exec rdapi python -m rdapi.cli list-users
docker compose exec rdapi python -m rdapi.cli reset-2fa alice             # schaltet die Zwei-Faktor-Anmeldung aus
docker compose exec rdapi python -m rdapi.cli setup-code                  # nur vor dem ersten Konto
```

## Erster Admin ohne Einrichtungsseite

Für automatische Installationen lässt sich der erste Admin beim Start anlegen statt über
die Einrichtungsseite:

| Variable | Bedeutung |
|---|---|
| `RDAPI_ADMIN_USER` | Benutzername des ersten Admins |
| `RDAPI_ADMIN_PASSWORD_FILE` | Datei mit dem Passwort, z. B. ein Docker-Secret |
| `RDAPI_ADMIN_PASSWORD` | das Passwort direkt (nur wenn keine Datei möglich ist) |

Das Konto wird nur angelegt, wenn es noch keinen Benutzer gibt; spätere Änderungen an
diesen Variablen wirken nicht mehr.
