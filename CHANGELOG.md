# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.0.3] - 2026-10-31

### Security

- Exclude local notes, environment files and key files from Docker build contexts.
- Refresh the pinned Python, Go and Alpine base images. All agent build paths
  use the same pinned Go image.

### Changed

- Update FastAPI to 0.162.0, Starlette to 1.10.0, Alembic to 1.20.1,
  pydantic-settings to 2.16.2, pycparser to 3.12 and oxlint to 1.90.0.
- Rebuild and sign agent 1.0.3 with the refreshed build image.

## [1.0.2] - 2026-10-24

Dependency updates and two hardening changes. Upgrade with
`sudo ops/update.sh`.

### Security

- The panel image installs Python packages with `--require-hashes`: every
  version in `backend/constraints.txt` carries the hashes of its files on PyPI,
  and a file that is not listed there is not installed, even under the same
  version number. Dependabot updates versions and hashes together;
  `python ops/pin_hashes.py` does it by hand.
- The agent release description is signed a second time, together with the
  signing date. Agent 1.0.2 checks this signature and prints the date in
  `sekvyr update --check`. Older agents check the first signature and update
  as before.
- undici 8.12.3 in the frontend build tools (four advisories; it is not part of
  the served interface).

### Changed

- FastAPI 0.158, Starlette 1.9, pydantic 2.14.1, SQLAlchemy 2.1.6 and smaller
  updates in the backend; React 19.3, Vite 8.3 and the rest of the frontend
  tools.
- Running the installer again with `--lang` writes the language to the agent
  config as well, so `sudo sekvyr add` speaks it too. `sudo sekvyr lang ru` or
  `en` changes it by hand.

## [1.0.1] - 2026-10-24

A security and fixes release. Upgrade with `sudo ops/update.sh`; read the
upgrade notes at the end first.

### Security

- The machine API no longer swaps a project for its namesake. A machine that
  asked for `group/project` used to get a project with the same name from
  another group once its own was deleted or its grant ended, and the agent
  rewrote the application's `.env` with those values. Now the address is taken
  literally, and only a project that really moved away from that group is
  found by the old address.
- The approval threshold can no longer be bypassed by changing an
  environment's parent, or by a maintainer who resets a developer's password
  and approves their own change. Only a role at or above the threshold
  approves, the author's level is fixed when the change is proposed, and
  pending changes of a disabled or re-roled account are withdrawn.
- A machine's grants hold only while the person who gave them can still give
  them. Servers and clusters of a disabled or demoted person stop receiving
  values; the panel says so before the change, and the owner can take them
  over.
- The migration preview no longer tells which keys exist in a folder the user
  cannot write to.
- Text from machine requests that are not yet authenticated (host name, client
  id, report fields) is stripped of control, bidi and zero-width characters
  before it reaches the audit log.
- certifi 2026.10.23 drops the compromised emSign roots, and the agent is built
  with Go 1.27.3 for the same certificate issue and earlier standard library
  fixes.
- Running the install command again on a connected server updates the agent
  through the installed agent, which checks the release signature, instead of
  trusting the panel for the binary.
- Images and compose: the panel code belongs to root, root filesystems are
  read-only, capabilities are dropped, and the database sits on a network with
  no way out. Release actions are pinned by commit, and a release checks the
  agent signature before anything is published.

### Fixed

- Migration from Infisical moves keys that come from imports; an odd answer
  from the source gives a clear error instead of a server error; the preview
  marks keys the migration will skip and says why.
- The edit dialog does not save an empty value after the current one failed to
  load, and an edit made over someone else's change is caught and shown as a
  diff.
- Browser tabs share sign-out and idle time: signing out or in as someone else
  in one tab reaches the others.
- Revoking a grant, lifting a deny and removing a group member ask first;
  closing a dialog with unsaved edits asks first; a lost connection says so; a
  deleted key can be brought back from the notice.
- An approved change in production is announced; the weekly digest counts
  approvals, migrations, restored snapshots, inheritance and copies.
- A refusal by a grant that requires two-factor authentication says so, and
  the owner can reset another account's second factor.
- quickstart refuses to install a second panel over a running one in another
  directory; `update.sh` pulls the release images before the backup and the
  checkout; maintenance scripts say when they need sudo; the safety dump of
  `restore.sh` is sealed; the watchdog reports again when the problem changes.
- The agent treats a release as newer than its own prereleases.
- Interface texts in Russian and English.

### Upgrade notes

- An agent connected without a group (`sudo sekvyr add api/prod`) now gets a
  refusal once a project with the same name appears in another group. Add the
  group: `sudo sekvyr add group/api/prod`.
- A project moved to another group before 1.0.1 is not found by its old group:
  the panel remembers moves only from this release on. Connect such
  applications again with the new group.
- An account disabled before 1.0.1 can be enabled again only by the owner.
- Servers and clusters whose creator was disabled or demoted below maintainer
  stop receiving values after the upgrade. Take them over on the server page.
- The database is on its own network now. A service of your own that joined
  the `internal` network to reach the database has to join `db` instead.

## [1.0.0] - 2026-10-13

First public release.

### Secrets

- Projects, environments, folders and keys. `.env` import and export,
  inherited values, search across the whole panel (Ctrl+K), navigation built
  for hundreds of projects.
- Every edit is a new version: history, diff between versions and over a
  period, rollback in one click. A deletion is a version too.
- Approvals by role: an edit from a role below the project threshold waits for
  someone more senior and does not reach the servers until then.
- Value hygiene: a note on why a key exists, a replacement date with reminders,
  required keys per project, the age of old values, findings such as
  `changeme` in production.
- Comparing environments without showing values, finding every place that
  holds the same value, keys nobody has read for a year.
- Migration from Infisical and HashiCorp Vault KV v2 with a preview. Existing
  values are not overwritten by default, and the source credentials are not
  stored.
- Browser-side encryption for selected projects: values are encrypted with a
  key the server never has.

### Access

- Access to secrets is granted by policies: who, where (project, environment,
  folder) and what, with `list` and `read` kept apart. A grant can expire and
  can require two-factor authentication.
- Roles set the hierarchy and the approval threshold. Passwords are at least
  12 characters and stored as bcrypt hashes, sign-in has TOTP and an attempt
  limiter kept in the database.

### Servers and clusters

- The agent for Linux: the panel shows a one-line install command with a
  one-time token, the agent keeps the `.env` files of the applications on the
  node up to date and runs a command after a change.
- The agent updates itself, forwards only, and only when the signature of the
  release checks out against the key built into it.
- Kubernetes: a pod presents its ServiceAccount token and the panel checks it
  against the cluster keys, so the agent sidecar needs no static secret in the
  cluster. An External Secrets Operator example for clusters that already run
  it.
- The machine API only reads secrets: a test in CI fails the build if a route
  that changes them appears there.

### Security

- Values are encrypted with AES-256-GCM by their environment key, which is
  wrapped by the root key. Ciphertext is bound to its place.
- The panel starts sealed. The root key is kept as shares (3 of 5 by default),
  as one key entered after every restart, or as a file on the server.
- The audit log is hash-chained and rechecked daily. A copy of its entries can
  go to an external webhook.
- The admin UI and the machine API are separate surfaces: the admin UI answers
  only the addresses on its allow-list.

### Operations

- One-command install: Docker, Caddy with a Let's Encrypt certificate, the
  panel from the released images or built from source, nightly encrypted
  backups and an out-of-container watchdog.
- Backups with a freshness check, restore with a safety dump first, upgrades
  that take a backup before the migrations.
- Emergency access: every value in one sealed file under an archive password
  of its own, opened by a separate utility without the panel.
- Alerts to Telegram and webhooks: a sealed or opened vault, blocked sign-in,
  changes in production, servers that stopped pulling secrets, a weekly
  digest. Alerts never carry values.
- The interface, the agent and the maintenance scripts speak English and
  Russian.
- Panel images for amd64 on GHCR; on other architectures the install builds
  the panel from source by itself. The agent image for Kubernetes is built for
  amd64 and arm64.

[1.0.3]: https://github.com/mihsergeev/Sekvyr/releases/tag/v1.0.3
[1.0.2]: https://github.com/mihsergeev/Sekvyr/releases/tag/v1.0.2
[1.0.1]: https://github.com/mihsergeev/Sekvyr/releases/tag/v1.0.1
[1.0.0]: https://github.com/mihsergeev/Sekvyr/releases/tag/v1.0.0
