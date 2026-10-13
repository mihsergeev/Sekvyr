# Security Policy

Sekvyr holds other people's passwords, keys and environment variables, so
security reports are very welcome.

## Reporting a vulnerability

Please report privately through GitHub Security Advisories ("Report a
vulnerability" on the repository's Security tab) rather than in a public issue.
Include what you did, what happened, and the version (the gear menu, "About"
shows it). Reports are usually acknowledged within a few days.

## Supported versions

The latest release is supported. Fixes go into a new release, not into patches
for old ones.

## What the design already assumes

The full model is in [docs/security-model.md](docs/security-model.md)
([по-русски](docs/security-model.ru.md)), the threat model in
[docs/threat-model.md](docs/threat-model.md). In short:

- **A database dump gives no values.** Every value is encrypted under its
  environment key, environment keys are wrapped with the root key, and the root
  key lives only in process memory. The panel starts sealed and serves nothing
  until the key or enough of its shares are entered.
- **Machines can only read.** The machine API has four routes that change
  anything, and none of them touches values; `ops/selfcheck.py` fails the build
  if a fifth one appears. Machine secrets are stored as hashes.
- **Agent updates are gated by an offline key.** The panel serves an agent
  release but cannot sign it; an agent installs an update only if the Ed25519
  signature verifies, the version is newer and the binary's hash matches the
  signed manifest.
- **Projects can be encrypted in the browser.** In that mode the panel stores
  opaque blobs and has no key to open them with.
- **The audit log is a hash chain**, and a copy can be shipped to a receiver the
  database owner cannot reach.

## Notes for whoever deploys it

**Keep the admin UI behind an allow-list or a VPN.** `SEKVYR_ALLOW_IPS` closes
it at the edge while the machine API stays open; an empty list closes nothing.

**Keep the root key shares, the backups and the backup password apart.** A
restore needs both the dump and the key, and that only protects you while they
are stored separately.

**The panel refuses weak secrets.** `SEKVYR_JWT_SECRET` and
`SEKVYR_ADMIN_PASSWORD` must be real values or it will not start. The panel does
not check `SEKVYR_DB_PASSWORD`: it lives in `.env`, quickstart generates a random
one, and on a manual install you set it yourself. The database is reachable only
inside the compose network. Change the owner password after the first sign-in
and turn on two-factor authentication.

**The emergency archive is every value in one file.** It is sealed with an
archive password of its own (12 characters or more), not the owner's sign-in
password; store it like the root key shares, not next to them.
