# Usage

**English** · [Deutsch](../de/usage.md) · [← Documentation](README.md)

## Setting up the app

In the RustDesk app under *Settings → Network → ID/Relay server*:

- **ID server** and **relay server:** your own RustDesk server, as before
- **API server:** the address of RDAPI, e.g. `https://rdapi.example.com`
- **Key:** the public key of your ID server, as before; paste it rather than typing it

Then sign in with your username and password (the account icon in the app). If
two-factor sign-in is on, the app then asks for the code from your authenticator app. Set
the API server on every device whose address book, device entry or history you want to
see, including the computers you connect to.

If single sign-on is set up (see [Configuration](configuration.md#single-sign-on)), the
app also shows a button such as “Login with Authelia”. It opens the browser; after you
have signed in at the provider, RDAPI asks you to confirm the sign-in for this
device, and the app is signed in. In the web interface, the same button is on the sign-in
page.

## What is synchronised

- **Address book:** every user has a personal address book with tags. Changes in the app
  or in the web interface are saved on the server and appear on all devices you are
  signed in on.
- **Shared address books:** admins can create further address books, e.g. “Family” or
  “Office”, and share them with single users or whole groups: *read only*, *read and
  change* or *full control*. The app shows them next to the personal address book; with
  “read only”, it cannot change them. If a user is covered several times, the highest
  permission counts. Admins see and manage all shared address books.
- **Devices:** every device with this API server reports itself regularly, also without
  a sign-in. It is matched by its RustDesk ID and an internal key the app sends along;
  once the server knows the key, reports with the same ID but a different key are
  ignored. A device belongs to the user who last signed in to the app on it, unless it
  already belongs to someone else and the key does not match; admins can change the owner
  in the web interface. In the app, your devices appear under “Accessible devices”,
  together with the devices of everyone who shares a group with you; admins see all
  devices there. Devices without an owner that have not reported for 30 days are removed.
- **History:** incoming connections are recorded by the device that is connected to, with
  start, duration, type and the address of the other side. Attempts that were not
  accepted are shown in grey. Files copied to or from a device during a connection
  (file transfer or copy and paste of files) are recorded as well, with direction,
  folder, number of files and the first file names.

## Web interface

Open the server's address in the browser and sign in with the same credentials as in the
app.

- **Devices:** name, ID, owner, operating system, version and online status; a click
  shows details such as CPU and memory, the latest connections, a note and the owner,
  which admins can change
- **History:** all incoming connections and, on a second tab, all file transfers, newest
  first, filterable by device
- **Address book:** add, edit and remove entries (ID, alias, note, tags) and manage
  tags with their colours; fields only the app knows, such as saved passwords, are kept
  and never shown. The tabs at the top switch between your own and the shared address
  books; admins create shared address books there and choose who may see them
- **Users** (admins only): create, edit, disable and delete users, set new passwords,
  make someone an admin, and manage groups and their members
- **Logins** (admins only): all sign-in attempts in the app and the web interface,
  successful or failed, with time and address, 20 per page
- **Activity** (admins only): who changed users, devices, backups or their own sign-in
  (password, two-factor sign-in, passkeys), and when, with the address
- **Backups** (admins only): see [Backups](#backups)
- **Account:** change your password, set up two-factor sign-in and passkeys, and end
  sessions in the browser or the app

The language menu and the theme button are at the top right. The choice is stored in the
browser.

## Two-factor sign-in

Under “Account” → “Two-factor sign-in” → “Set up”, scan the code with an authenticator
app on your phone or with your password manager, then enter the six-digit code to
confirm. You then get eight **recovery codes**: write them down or store them in your
password manager. They are shown only once, and each works once, in case your phone is
lost.

From then on, the web interface and the RustDesk app ask for a code after the password.
In the web interface, a recovery code works instead of the code; in the app, use the code
from the authenticator app. New recovery codes and turning it off are on the same page and
need your password and a code.

If someone lost both phone and recovery codes, an admin turns two-factor sign-in off for
them under “Users”, or on the command line (see
[Configuration](configuration.md#command-line)).

## Passkeys and security keys

Under “Account” → “Passkeys and security keys”, everyone can add passkeys: the fingerprint,
face or PIN of a phone or computer, or a FIDO2 security key. Give each one a name so you
can tell them apart later.

- **Sign in without a password:** the sign-in page shows “Sign in with a passkey” as soon
  as a passkey exists. The passkey checks fingerprint, face or PIN itself, so no second
  step follows.
- **As second factor:** once you have a passkey, signing in with your password in the web
  interface also asks for the passkey (or the code from your authenticator app, if that is
  on too).
- **Recovery codes:** with your first passkey you get eight recovery codes, unless you
  already have some; each works once if no passkey is at hand.

Passkeys need HTTPS and belong to the address they were created at, e.g.
`rd.example.com`; after moving to another address, add them again. The RustDesk app cannot
use passkeys; it keeps signing in with password (and code). With a provider such as
Authelia, passkeys set up there also work for the app through single sign-on.

An admin removes all passkeys and the code of a user under “Users” → “Turn off two-factor
sign-in”, or with `rdapi.cli reset-2fa`.

## Backups

The server backs up its database every day and keeps the last seven backups (see
[Configuration](configuration.md#settings)). Under “Backups”, admins can:

- **Back up now**, e.g. before an update
- **Download** a backup to keep a copy somewhere else
- **Restore** a backup: all changes since then are lost; the current state is backed up
  first, so you can go back
- **Upload** a downloaded backup, e.g. after moving to a new server, and then restore it

After restoring, everyone who signed in after the backup was made has to sign in again.

## Troubleshooting

**Sign-in in the app fails:** after too many failed attempts, the server blocks further
attempts for a while (see [Configuration](configuration.md#settings)). The “Logins” page
shows which attempts arrived and why they failed.

**The device does not appear under “Devices”:** check the API server on that device. It
reports itself shortly after; the app may need a restart after changing the setting. If
the device was reinstalled and now sends a new key with its old RustDesk ID, its reports
are ignored; an admin removes it under “Devices”, and it is registered again on its next
report.

**Single sign-on ends with “The sign-in with the provider failed”:** check the redirect
URI at the provider (`https://<your address>/oidc/callback`) and the client secret. The
provider must be reachable from the server running RDAPI. If the server sees a
different address than the browser (e.g. behind an unusual proxy), set
`RDAPI_PUBLIC_URL`.

**An error about the key when connecting:** the key in the app does not exactly
match the key of your ID server. Clear the field and paste the key again; a space or line
break at the end is enough to break it.

**Signed out, connections work; signed in, they fail with “Failed to secure tcp: deadline
has elapsed”:** a signed-in app asks the ID server for an encrypted connection, and some
ID server versions do not answer this request; the official ID server (hbbs) does not up to
version 1.1.16. This is not caused by the API server; it happens with any API server. The
fix is RustDesk's [pull request #706](https://github.com/rustdesk/rustdesk-server/pull/706). Until an ID server release contains it, sign
out in the app before connecting.
