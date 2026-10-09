# Bedienung

[English](../en/usage.md) · **Deutsch** · [← Dokumentation](README.md)

## App einrichten

In der RustDesk-App unter *Einstellungen → Netzwerk → ID-/Relay-Server*:

- **ID-Server** und **Relay-Server:** dein eigener RustDesk-Server, wie bisher
- **API-Server:** die Adresse von RDAPI, z. B. `https://rdapi.example.com`
- **Schlüssel:** der öffentliche Schlüssel deines ID-Servers, wie bisher; am besten
  einfügen statt abtippen

Melde dich dann mit Benutzername und Passwort an (Kontosymbol in der App). Ist die
Zwei-Faktor-Anmeldung eingeschaltet, fragt die App danach nach dem Code aus deiner
Authenticator-App. Trag den API-Server auf jedem Gerät ein, dessen Adressbuch,
Geräteeintrag oder Verlauf du sehen willst, also auch auf den Rechnern, mit denen du dich
verbindest.

Ist die Anmeldung über einen Anbieter eingerichtet (siehe
[Konfiguration](configuration.md#anmeldung-über-einen-anbieter)), zeigt die App zusätzlich
einen Knopf wie „Login with Authelia“. Er öffnet den Browser; nach der Anmeldung beim
Anbieter fragt RDAPI, ob du die Anmeldung für dieses Gerät bestätigst, und die App
ist angemeldet. In der Weboberfläche steht derselbe Knopf auf der Anmeldeseite.

## Was abgeglichen wird

- **Adressbuch:** Jeder Benutzer hat ein persönliches Adressbuch mit Tags. Änderungen in
  der App oder in der Weboberfläche werden auf dem Server gespeichert und erscheinen auf
  allen Geräten, auf denen du angemeldet bist.
- **Geräte:** Jedes Gerät mit diesem API-Server meldet sich regelmäßig, auch ohne
  Anmeldung. Zugeordnet wird es über seine RustDesk-ID und eine interne Kennung, die die
  App mitschickt; kennt der Server die Kennung, ignoriert er Meldungen mit derselben ID,
  aber anderer Kennung. Ein Gerät gehört dem Benutzer, der sich zuletzt in der App darauf
  angemeldet hat, außer es gehört schon jemand anderem und die Kennung passt nicht; Admins
  können den Besitzer in der Weboberfläche ändern. In der App erscheinen deine Geräte unter
  „Zugängliche Geräte“. Geräte ohne Besitzer, die sich 30 Tage nicht gemeldet haben,
  werden entfernt.
- **Verlauf:** Eingehende Verbindungen meldet das Gerät, mit dem verbunden wird, mit
  Beginn, Dauer, Art und der Adresse der Gegenseite. Nicht angenommene Versuche sind grau.

## Weboberfläche

Öffne die Adresse des Servers im Browser und melde dich mit denselben Zugangsdaten wie in
der App an.

- **Geräte:** Name, ID, Besitzer, Betriebssystem, Version und Online-Status; ein Klick
  zeigt Details wie CPU und Arbeitsspeicher, die letzten Verbindungen, eine Notiz und den
  Besitzer, den Admins ändern können
- **Verlauf:** alle eingehenden Verbindungen, neueste zuerst, nach Gerät filterbar
- **Adressbuch:** Einträge anlegen, bearbeiten und entfernen (ID, Alias, Notiz, Tags)
  und Tags mit ihren Farben verwalten; Felder, die nur die App kennt, z. B. gespeicherte
  Passwörter, bleiben erhalten und werden nie angezeigt
- **Benutzer** (nur Admins): Benutzer anlegen, bearbeiten, sperren und löschen, neue
  Passwörter setzen, jemanden zum Admin machen
- **Anmeldungen** (nur Admins): die letzten 200 Anmeldeversuche in App und
  Weboberfläche, erfolgreich oder fehlgeschlagen, mit Zeit und Adresse
- **Aktivität** (nur Admins): wer wann Benutzer, Geräte, Sicherungen oder die eigene
  Anmeldung (Passwort, Zwei-Faktor-Anmeldung, Passkeys) geändert hat, mit Adresse
- **Sicherungen** (nur Admins): siehe [Sicherungen](#sicherungen)
- **Konto:** eigenes Passwort ändern, Zwei-Faktor-Anmeldung und Passkeys einrichten und
  Sitzungen im Browser oder in der App beenden

Sprachmenü und Design-Knopf sind oben rechts. Die Auswahl merkt sich der Browser.

## Zwei-Faktor-Anmeldung

Unter „Konto“ → „Zwei-Faktor-Anmeldung“ → „Einrichten“ scannst du den Code mit einer
Authenticator-App auf deinem Telefon oder mit deinem Passwort-Manager und bestätigst mit
dem sechsstelligen Code. Danach bekommst du acht **Wiederherstellungscodes**: Schreib sie
auf oder speichere sie in deinem Passwort-Manager. Sie werden nur einmal angezeigt, und
jeder funktioniert einmal, falls das Telefon verloren geht.

Ab dann fragen Weboberfläche und RustDesk-App nach dem Passwort nach einem Code. In der
Weboberfläche geht statt des Codes auch ein Wiederherstellungscode; in der App nimmst du
den Code aus der Authenticator-App. Neue Wiederherstellungscodes und das Ausschalten
findest du auf derselben Seite; beides braucht dein Passwort und einen Code.

Hat jemand Telefon und Wiederherstellungscodes verloren, schaltet ein Admin die
Zwei-Faktor-Anmeldung unter „Benutzer“ für ihn aus, oder auf der Kommandozeile (siehe
[Konfiguration](configuration.md#kommandozeile)).

## Passkeys und Sicherheitsschlüssel

Unter „Konto“ → „Passkeys und Sicherheitsschlüssel“ kann jeder Passkeys hinzufügen:
Fingerabdruck, Gesicht oder PIN eines Telefons oder Rechners, oder einen
FIDO2-Sicherheitsschlüssel. Gib jedem einen Namen, damit du sie später unterscheiden
kannst.

- **Anmelden ohne Passwort:** Die Anmeldeseite zeigt „Mit Passkey anmelden“, sobald es
  einen Passkey gibt. Der Passkey prüft Fingerabdruck, Gesicht oder PIN selbst, deshalb
  folgt kein zweiter Schritt.
- **Als zweiter Faktor:** Sobald du einen Passkey hast, fragt die Weboberfläche nach der
  Anmeldung mit Passwort auch nach dem Passkey (oder nach dem Code aus der
  Authenticator-App, wenn der auch eingeschaltet ist).
- **Wiederherstellungscodes:** Mit dem ersten Passkey bekommst du acht
  Wiederherstellungscodes, falls du noch keine hast; jeder funktioniert einmal, wenn kein
  Passkey zur Hand ist.

Passkeys brauchen HTTPS und gehören zu der Adresse, unter der sie angelegt wurden, z. B.
`rd.example.com`; nach einem Umzug auf eine andere Adresse legst du sie neu an. Die
RustDesk-App kann keine Passkeys nutzen; sie meldet sich weiter mit Passwort (und Code)
an. Mit einem Anbieter wie Authelia funktionieren dort eingerichtete Passkeys über die
Anmeldung beim Anbieter auch für die App.

Ein Admin entfernt alle Passkeys und den Code eines Benutzers unter „Benutzer“ →
„Zwei-Faktor-Anmeldung ausschalten“, oder mit `rdapi.cli reset-2fa`.

## Sicherungen

Der Server sichert seine Datenbank jeden Tag und behält die letzten sieben Sicherungen
(siehe [Konfiguration](configuration.md#einstellungen)). Unter „Sicherungen“ können
Admins:

- **Jetzt sichern**, z. B. vor einem Update
- eine Sicherung **herunterladen**, um eine Kopie woanders aufzubewahren
- eine Sicherung **zurückspielen**: Alle Änderungen seitdem gehen verloren; der jetzige
  Stand wird vorher gesichert, du kannst also zurück
- eine heruntergeladene Sicherung **hochladen**, z. B. nach dem Umzug auf einen neuen
  Server, und sie dann zurückspielen

Nach dem Zurückspielen muss sich jeder neu anmelden, der sich erst nach der Sicherung
angemeldet hat.

## Fehlersuche

**Anmeldung in der App klappt nicht:** Nach zu vielen Fehlversuchen sperrt der Server
weitere Versuche für eine Weile (siehe [Konfiguration](configuration.md#einstellungen)).
Die Seite „Anmeldungen“ zeigt, welche Versuche angekommen sind und warum sie
fehlgeschlagen sind.

**Das Gerät erscheint nicht unter „Geräte“:** Prüfe den API-Server auf diesem Gerät. Es
meldet sich kurz danach; nach dem Ändern der Einstellung muss die App eventuell neu
gestartet werden. Wurde das Gerät neu installiert und schickt nun mit seiner alten
RustDesk-ID eine neue Kennung, werden seine Meldungen ignoriert; ein Admin entfernt es
unter „Geräte“, dann wird es bei der nächsten Meldung neu angelegt.

**Die Anmeldung über den Anbieter endet mit „Die Anmeldung beim Anbieter ist
fehlgeschlagen“:** Prüfe beim Anbieter die Rücksprung-Adresse
(`https://<deine Adresse>/oidc/callback`) und das Client-Geheimnis. Der Anbieter muss vom
Server aus erreichbar sein, auf dem RDAPI läuft. Sieht der Server eine andere
Adresse als der Browser (z. B. hinter einem ungewöhnlichen Proxy), setze
`RDAPI_PUBLIC_URL`.

**Fehler zum Schlüssel beim Verbinden:** Der Schlüssel in der App stimmt nicht genau mit
dem deines ID-Servers überein. Feld leeren und den Schlüssel neu einfügen; schon ein
Leerzeichen oder Zeilenumbruch am Ende reicht für den Fehler.

**Abgemeldet klappen Verbindungen, angemeldet scheitern sie mit „Failed to secure tcp:
deadline has elapsed“:** Eine angemeldete App bittet den ID-Server um eine verschlüsselte
Verbindung, und manche Versionen des ID-Servers beantworten diese Anfrage nicht; der
offizielle ID-Server (hbbs) tut es bis Version 1.1.16 nicht. Das liegt nicht am API-Server,
es passiert mit jedem API-Server. Die Korrektur ist RustDesks
[Pull Request #706](https://github.com/rustdesk/rustdesk-server/pull/706). Bis ein Release des ID-Servers sie enthält, meldest du dich vor
dem Verbinden in der App ab.
