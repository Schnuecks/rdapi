# Installation

[English](../en/installation.md) · **Deutsch** · [← Dokumentation](README.md)

## Voraussetzungen

Du brauchst Docker mit Docker Compose 2.24 oder neuer. Das Image gibt es für PCs und
Server (amd64) und für 64-Bit-ARM (arm64, z. B. Raspberry Pi 4/5 mit 64-Bit-System).
Docker wählt automatisch das passende.

RDAPI kümmert sich nur um Anmeldung, Adressbuch, Geräte und Verlauf. Die
Verbindungen selbst laufen weiter über deinen eigenen RustDesk-ID- und Relay-Server, an
dem sich nichts ändert.

## Schnellstart

```bash
mkdir rdapi && cd rdapi
curl -O https://raw.githubusercontent.com/schnuecks/rdapi/main/compose.yaml
mkdir data && chown 1000:1000 data
docker compose up -d
docker compose logs rdapi
```

Der Server ist jetzt unter `http://<server>:21114` erreichbar. Beim ersten Aufruf legst
du das Admin-Konto an; den Einrichtungscode dafür findest du im Log (siehe
[Erstes Admin-Konto](#erstes-admin-konto)). Danach richtest du die App ein, wie unter
[Bedienung](usage.md#app-einrichten) beschrieben.

Der Ordner `data` muss für den Benutzer beschreibbar sein, unter dem der Container läuft
(`PUID` und `PGID`, Standard 1000). Weitere Einstellungen kommen in eine optionale `.env`
neben `compose.yaml`, siehe [Konfiguration](configuration.md).

## Erstes Admin-Konto

Solange es keinen Benutzer gibt, führt jede Seite zu **Admin-Konto anlegen**. Der
Einrichtungscode schützt diesen Schritt: Er steht bei jedem Start im Container-Log und
lässt sich jederzeit erneut anzeigen mit

```bash
docker compose exec rdapi python -m rdapi.cli setup-code
```

Sobald das Konto existiert, ist die Einrichtungsseite geschlossen und der Code gelöscht.
Weitere Benutzer legst du in der Weboberfläche unter „Benutzer“ an. Für automatische
Installationen legen `RDAPI_ADMIN_USER` und `RDAPI_ADMIN_PASSWORD_FILE` den ersten Admin
stattdessen beim Start an, siehe
[Konfiguration](configuration.md#erster-admin-ohne-einrichtungsseite).

## Hinter einem Reverse Proxy

Für den Zugriff aus dem Internet gehört der Server hinter einen Reverse Proxy mit HTTPS.
Die App kommt nicht durch eine zusätzliche Anmeldeseite wie Authelia, deshalb brauchen
die Pfade unterschiedlichen Schutz:

| Pfad | Zweck | Empfohlener Schutz |
|---|---|---|
| `/api/login` | Anmeldung aus der App | IP-Sperrliste, WAF und Rate-Limit |
| `/api/…` | übrige App-Schnittstelle | IP-Sperrliste und WAF, keine Anmeldeseite |
| alles andere | Weboberfläche | Anmeldeseite (z. B. Authelia) und IP-Sperrliste |

Die Weboberfläche hat eine eigene Anmeldung mit denselben Zugangsdaten wie die App. Sie
bleibt also geschützt, auch wenn eine Regel im Proxy einmal nicht greift.

`compose.traefik.yml` ist ein fertiger Stack für Traefik mit diesen drei Routern:

```bash
mkdir rdapi && cd rdapi
curl -o compose.yml https://raw.githubusercontent.com/schnuecks/rdapi/main/compose.traefik.yml
curl -o .env https://raw.githubusercontent.com/schnuecks/rdapi/main/.env.example
chmod 600 .env                                  # Werte prüfen, DOMAIN setzen
mkdir data && chown 1000:1000 data              # = PUID:PGID aus .env
docker compose up -d
docker compose logs rdapi                # zeigt den Einrichtungscode
```

Passe dann die **Middleware-Namen** in `compose.yml` an dein Traefik an. Die Router haben
feste Prioritäten, damit `/api/login` vor `/api/` und `/api/` vor der Weboberfläche
greift.

Die echte Adresse eines Besuchers übernimmt der Server aus dem Header
`X-Forwarded-For`, aber nur, wenn die Anfrage aus einem lokalen oder privaten Netz kommt,
wo üblicherweise der Reverse Proxy steht. Von allen anderen Adressen wird der Header
ignoriert, damit niemand die Begrenzung der Fehlversuche mit einer erfundenen Adresse
umgehen kann. Steht dein Proxy woanders, siehe
[Konfiguration](configuration.md#adresse-des-reverse-proxys).

## Aktualisieren

```bash
docker compose pull && docker compose up -d
```

Die Datenbank wird beim Start automatisch angepasst. Was sich in jeder Version geändert
hat, steht im [CHANGELOG](../../CHANGELOG.md).

## Daten und Sicherung

Alles liegt in `data/rdapi.sqlite3`. Der Server sichert die Datei jeden Tag nach
`data/backups/` und behält die letzten sieben Sicherungen; Admins erstellen, laden und
spielen Sicherungen in der Weboberfläche unter „Sicherungen“ zurück (siehe
[Bedienung](usage.md#sicherungen)). Für eine Kopie an einem anderen Ort sicherst du den
ganzen Ordner `data` oder lädst regelmäßig eine Sicherung herunter.

Verlauf und Anmeldeprotokoll werden nach 365 Tagen gelöscht (`RDAPI_HISTORY_DAYS`).

## Umzug von einem anderen API-Server

1. RDAPI auf einer Test-Subdomain neben dem alten Server starten. Laufen beide auf
   demselben Host, in `.env` für `COMPOSE_PROJECT_NAME` und `SVC` Namen wählen, die der
   alte Stack nicht benutzt.
2. In einer App den API-Server auf die Testadresse stellen und prüfen: Anmeldung,
   Adressbuch (Eintrag anlegen, Tag setzen, umbenennen, löschen), das Gerät erscheint
   unter „Geräte“, eine Verbindung erscheint im Verlauf.
3. Wenn alles passt: alten Server stoppen, in `.env` die endgültige `DOMAIN` setzen,
   `docker compose up -d` ausführen und alle Apps auf die endgültige Adresse umstellen.

Benutzer und Adressbücher werden vom alten Server **nicht** übernommen; lege die Benutzer
neu an und fülle die Adressbücher in der App.
