# BackMeUp

A local-first Windows desktop app that backs up MySQL and MariaDB databases to
this computer and to Google Drive, and writes files you can actually restore.

Tauri 2 (Rust) + React + TypeScript. Nothing leaves the machine unless you
choose Google Drive as a destination.

---

## What a backup is

Each backup is one `.sql` file containing the **schema and every row of every
table and view** in the database.

The file is written by a logical dumper written in Rust — it does **not** shell
out to `mysqldump`, so a password can never appear in a command line or in a
process list.

### What is guaranteed

| | |
|---|---|
| **One consistent snapshot** | The whole dump is read inside a single `START TRANSACTION WITH CONSISTENT SNAPSHOT` (REPEATABLE READ), so every InnoDB table comes from the same point in time. |
| **Nothing is locked** | No `LOCK TABLES`, no `FLUSH`, no DDL, no `SET GLOBAL`. Your site keeps serving while a backup runs. |
| **All or nothing** | Any SQL error — a missing privilege, a dropped table, a lost connection — aborts the run and the partial file is deleted. There is no "succeeded but incomplete" backup. |
| **Nothing skipped silently** | If a row does not match its table, the run stops rather than saving a table that is quietly empty. |
| **Columns by name** | `SELECT *` is never used. `SELECT *` omits invisible columns and returns generated ones that cannot be inserted, so columns are always named. |
| **Restorable order** | Views are written *after* the tables they name, because MySQL and MariaDB both refuse to create a view whose tables do not exist yet. |
| **A checksum** | The SHA-256 of the finished file is computed while it is written and shown in the history, so a file can be checked later. |
| **No secrets at rest** | Database passwords, SSH keys and OAuth tokens live in the Windows Credential Manager, never in the app's database. |

### What is *not* in the file

- Triggers, stored procedures, functions and events. These are server objects
  rather than table contents and are not part of this format.
- Tables using a non-transactional engine (MyISAM, ARIA) are not
  snapshot-consistent. Their rows can be read mid-write and will not match the
  transactional tables in the same file.
- A table with more than 5,000,000 rows, or a database with more than 200,000
  tables, fails the run rather than being truncated.

Running a backup while you are altering the schema (`ALTER TABLE`, `DROP
TABLE`) can produce a file that does not match the new shape. Back up when the
schema is settled.

---

## Install

Builds are produced in `src-tauri/target/release/bundle/`:

| File | Size | Notes |
|---|---|---|
| `msi/BackMeUp_0.1.0_x64_en-US.msi` | 5.1 MB | Recommended for school and office machines. |
| `nsis/BackMeUp_0.1.0_x64-setup.exe` | 3.9 MB | Alternative installer. |

The builds are **unsigned**, so Windows SmartScreen will say *"Windows
protected your PC"* → **More info → Run anyway**.

The app needs the [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/),
which is present on Windows 11 and on any current Windows 10.

Both installers and the development build use the identifier
`com.backmeup.desktop`, so they share one database, one set of settings and one
Windows Credential Manager entry. Installing over a development build keeps
everything.

### Where your data lives

| | |
|---|---|
| App database | `%APPDATA%\com.backmeup.desktop\backmeup.db` (SQLite) |
| Secrets | Windows Credential Manager, under `BackMeUp:*` |
| Local backups | The folder you choose, under `BackMeUp/<database>/<day>/` |
| Drive backups | `BackMeUp/<database>/<day>/` in your Google Drive |

The same tree is used for both destinations, so a local copy and a Drive copy
of the same run are identical in shape.

---

## Build from source

### Prerequisites

- Rust 1.82 or newer (`rustup`)
- Node.js 20 or newer and npm
- The Tauri CLI, via the npm dependencies (`npm install`)

### Commands

```bash
npm install                # install dependencies
npm run tauri dev          # run the app for development
npm run tauri build        # build the installers
```

The build output lands in:

```text
src-tauri/target/release/bundle/msi/BackMeUp_0.1.0_x64_en-US.msi
src-tauri/target/release/bundle/nsis/BackMeUp_0.1.0_x64-setup.exe
```

### Checks

```bash
npm run typecheck                  # TypeScript
cargo test --manifest-path src-tauri/Cargo.toml
```

The Rust test suite covers the dumper's escaping and ordering rules, the
credential handling, the SSH host-key pinning, the OAuth flow, and the history
schema.

---

## Google Drive setup

The app talks to Google Drive through the official API using OAuth 2.0 with
PKCE.

1. In the [Google Cloud console](https://console.cloud.google.com/), enable
   the **Google Drive API** for a project.
2. Create an **OAuth client ID** of type **Desktop app**.
3. Put the client id in `src-tauri/src/drive.rs` (`OAUTH_CLIENT_ID`). It is a
   public identifier and belongs in the source.
4. Put the client secret **in your build environment, not in the repository**:

   ```powershell
   . .\secrets.local.ps1          # sets $env:BACKMEUP_OAUTH_CLIENT_SECRET
   npm run tauri build
   ```

   ```bash
   BACKMEUP_OAUTH_CLIENT_SECRET=... npm run tauri build
   ```

   `src-tauri/src/drive.rs` reads it at compile time
   (`option_env!("BACKMEUP_OAUTH_CLIENT_SECRET")`). A build made without it
   still installs and still backs up to a local folder; it simply says
   *"This copy of BackMeUp was built without Google Drive support"* instead of
   opening a sign-in that cannot finish.
5. Configure the **OAuth consent screen** and add yourself as a test user.

> **Publish the consent screen before relying on it.** While a consent screen is
> in *Testing* mode, Google issues refresh tokens that expire after seven
> days, so the app will ask you to sign in again every week. Set the consent
> screen to *Production* (and publish it) for tokens that keep working.

A desktop app cannot keep a client secret secret — the binary contains it
either way. Keeping it out of the repository stops it from being copied around
as plain text, and the OAuth client is restricted instead: use a Desktop app
client, add only the redirect URIs you need, and keep the consent screen in
production.

---

## Restoring a backup

The file is plain SQL and restores with the standard tools:

```bash
mysql --user=<user> --password <database> < BackMeUp/shop/2026-10-20/shop.sql
```

or, in phpMyAdmin, select the target database → **Import** → choose the file.
Do not tick "Add DROP TABLE" — the file already contains `DROP TABLE IF
EXISTS` for each table.

The file starts by dropping the target's tables, so **importing replaces the
data in the database you import into**. Import into a fresh database unless
you mean to overwrite.

> A backup file contains your data. Treat it like a password.

---

## Updates

The app can update itself.

- On launch it reads one small file, `latest.json`, from this repository. That
  is the whole check: one request, no data sent, and a machine with no network
  hears nothing at all.
- When a newer version exists, a prompt offers to install it. **Closing the
  prompt does not lose the offer** — the notice stays in the bell in the title
  bar until the version is installed.
- The download is checked against the update signing key before it is run, so a
  tampered file is refused rather than installed.
- The check runs at most once a day, and never during a backup.

The private half of the signing key is **not** in this repository. It lives on
the machine that made the release, and its passphrase is in Windows Credential
Manager under `BackMeUp:updater-signing-key`. Lose either and updates can no
longer be published.

## Notices

Some things are worth saying once, and a toast is gone in five seconds. Those
live in the bell in the title bar:

- **An update is available** — with the button that installs it.
- **A stored password was refused** — with the button that re-enters it. A
  password that was rotated on the server leaves the saved copy behind, and
  without this every backup fails with a message that does not say what to do.
- **What was backed up** — which database, how many rows, and how many of the
  saved databases have been backed up so far.

Notices are worked out from the facts the app already keeps, so they cannot go
stale or disagree with the history.

The **Check all** button on the Databases screen tests every saved connection
and reports which passwords the server no longer accepts.

---

## Releasing

`latest.json` is committed to this repository and points at the newest release.
It is rewritten as part of every release.

A release is one command:

```powershell
python release.py 0.1.1
```

which writes the version into `package.json`, `Cargo.toml` and
`tauri.conf.json`, builds the installers with the OAuth secret and the update
signing key supplied through the environment, turns the signature the build
produced into `latest.json`, commits, pushes, tags, and uploads the installers
to the release.

Two secrets are needed, and neither is in the repository:

| Secret | Where it comes from |
|---|---|
| `BACKMEUP_OAUTH_CLIENT_SECRET` | `secrets.local.ps1` (gitignored) |
| The update signing passphrase | Windows Credential Manager, `BackMeUp:updater-signing-key` |

---

## Project layout

```text
src/                     React front end
  components/            Panels, dialogs, title bar, toasts
  screens/               Dashboard, databases, history, settings, security
  lib/api.ts             Typed bindings to the Rust commands
src-tauri/
  src/mysqldump.rs       The logical dumper
  src/runs.rs            Backup orchestration, staging, upload, history
  src/drive.rs           Google Drive: OAuth, folders, upload
  src/dbconn/            One module per engine; the only place sockets open
  src/credentials.rs     Windows Credential Manager
  src/ssh.rs             SSH tunnel, with pinned host keys
  src/db.rs              Local SQLite schema and migrations
```

---

## Licence

Add one before publishing publicly.
