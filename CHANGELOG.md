# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

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

[1.0.0]: https://github.com/mihsergeev/Sekvyr/releases/tag/v1.0.0
