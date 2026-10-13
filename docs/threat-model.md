# Threat model

[Русская версия](threat-model.ru.md)

This document answers two questions: what Sekvyr protects against, and what it
does not. The second matters more - a system whose edges are unclear is worse
than no system, because people rely on it where they should not.

## What is protected

The values of secrets: database passwords, payment keys, tokens. Everything else
(project names, the structure of environments, the access log) is protected
weakly and on purpose: the interface, search and permissions all work on it.

## Who the adversary is

| Adversary | What they have |
| --- | --- |
| The internet | the panel address, nothing more |
| A compromised application server | a node or pod running the agent |
| An employee with panel access | their account and its granted rights |
| Whoever obtained a backup | a dump file stolen from the offsite copy |
| A database administrator | full access to Postgres |
| Root on the panel host | everything the panel has |

## From the internet

**What stops them.** The admin UI sits behind an address allow-list at the edge
(`compose.caddy.yml`); only the machine API `/api/v1/machine/*` is public. It
only reads values: four of its routes change anything (token, report, revoke,
enroll), none of them touches values, and that is checked statically by
`ops/selfcheck.py` rather than promised in prose. The Docker subnet is not on
the allow-list: without IPv6 on the caddy network every IPv6 client would arrive
from it. Human sign-ins are rate-limited; a burst of failures blocks the address
and goes into the alerts.

**What remains.** Availability: the panel can be flooded. Values do not leak,
but servers stop receiving updates - which is survivable because the agent keeps
the last value locally.

## A compromised application server

**What stops them.** A machine identity can only read, and only the environment
it was granted. Its token lives 15 minutes, is bound to the identity and to an
address allow-list when one is set. In Kubernetes there is no static secret at
all: the pod proves itself with a ServiceAccount token signed by the cluster and
valid for an hour.

**What remains.** A compromised server gives up ITS OWN secrets: they are in its
memory and in the file the whole thing exists for. Sekvyr limits the blast
radius - such a server gets no other environment and cannot corrupt the shared
vault - but it does not protect what that server is entitled to anyway.

## An employee with panel access

**What stops them.** Permissions are closed by default: only what a policy
grants. `list` and `read` are separate, so one can see key names without seeing
values. In a protected project an edit is confirmed by a higher role. Every read
and write by a person goes into a hash-chained audit log; machines, which ask
every minute, are logged on a new set of values, a new address and once a day. A role can only be granted below
your own, and the last owner cannot be demoted. A viewer only sees keys and
reads values, even if a write permission reaches them through a group. Accounts
are created and changed by a maintainer or above.

**What remains.** Anyone granted a value can copy it elsewhere - every secrets
store ends there. The log says who read what and when; it does not prevent
reading.

## Whoever obtained a backup

**What stops them.** The dump is encrypted with its own password (scrypt plus
AES-256-GCM, the `SEKVYR-SEALED-1` format), and the values inside it are
encrypted again with the root key, which is not in the dump. Chunks cannot be
swapped or dropped: the chunk index and the "last chunk" flag are part of the
associated data, so a truncated dump does not open.

**What remains.** A weak password. It is attacked offline, with no rate limits,
with the file in hand, and storing it next to the file is pointless. The dump
password (`secret/backup.pass`) is created by the backup script itself; the
12-character minimum applies to the emergency archive password, which a person
chooses.

## A database administrator

**What stops them.** The database holds ciphertext only. Every value is bound to
its place: environment, secret id, key name and version number are part of the
cipher's associated data, and on reading the panel also checks that the key's
name and folder match those of the version. Copying a value from dev to prod,
swapping two values, or giving a value another key's name or folder by editing
tables all fail - the read errors out instead of silently returning something
plausible.

**What remains.** Rolling back: with write access to the tables one can make an
older version current again or point an environment at another parent, and
every value involved decrypts honestly. Only the audit log and backups show it.
And deletion. Anyone with database access can destroy it; backups
answer that, not cryptography. And the log: the chain catches edits in the
middle, but does not prevent trimming the log from the end and continuing with a
fresh start. A copy on an external receiver (`SEKVYR_AUDIT_WEBHOOK`) is what
answers that.

## Root on the panel host

The honest answer: **root on the panel host equals access to every value of
ordinary projects** while the panel is unsealed. Projects with browser-side
encryption are the exception: the server only holds their values as blobs, and
the key to them is not in the panel at all. The exception holds until the next
time someone types the project password: the browser gets the encrypting page
from the same panel, and root can replace it (details in [docs/e2e.md](e2e.md)).
The root key lives in the memory of the process, and whoever owns the process
owns the key.

What that changes:

- The shares mode (3 of 5) means that after a reboot the panel comes up
  **sealed**, and without people no values are served. This is the only defence
  against "the disk was taken" and "root was obtained at night with nobody
  watching".
- Auto-unseal (the key in a file) is more convenient and weaker: the key lies
  right there. The panel warns when the intent and the settings disagree, and the
  key file is kept outside the database volume so backups do not carry it away
  with the ciphertext.

## Alerts and what they can see

Channel settings live in the database in plain text, and the bot token also
lives in the heartbeat file `data/heartbeat` with mode 0600. This is a
deliberate trade: a panel that came up sealed cannot decrypt its own token, and
that is exactly when it has to speak. A bot token is the right to write into one
chat, not a key to the secrets.

Addresses the panel calls itself (webhooks, the Bot API mirror) are validated on
save: `https` only, public addresses only. Otherwise configuring alerts becomes
an SSRF into the perimeter. The residual risk is DNS rebinding - a name that
resolves to a public address on save and to an internal one later. Addresses set
in `.env` are not validated: they come from whoever already runs the server.

## Migration from another vault

The panel calls the address a human gave it, internal ones included: self-hosted
Infisical and Vault almost always live inside the perimeter, so the "public
addresses only" check used for webhooks cannot apply. Which means the right to
run a migration is the right to make the panel send a request anywhere inside
the network and see the response code. Not more than that: loopback (inside the
container it is the panel itself), link-local with cloud metadata and other
cloud service addresses are refused, and the body of a foreign response never
comes back, only what Vault or Infisical put into their own error fields. DNS
rebinding gets around the address check the same way as for webhooks, and then
yields nothing but the response code.

The limit: migration, the list of Infisical projects included, is available to
maintainers and above, and only into an environment where they have the `write`
right. Source credentials are not
stored, and values never reach the audit log.

## The emergency archive

The most dangerous place in the system: every value in one file under one
password. Hence it is built by the owner only, with a password and, if the
owner has it on, the second factor, and the event goes into the audit log and
the alerts. Building it cannot
be hidden - if it was not planned, someone will know.

## Custom logo

**What stops it.** Only the panel owner can change the logo, and every change
goes to the audit log. The file type is detected from the content, not the
name. An SVG with scripts, event handlers or external references is rejected on
upload. The image is served with a policy that forbids loading anything and in a
sandbox: opened directly by its address, it gets no access to the panel.

**What remains.** The images and their settings are available without signing
in, because the sign-in screen draws them. A logo is not a secret, but it shows
whose panel this is.

## Supply chain

The agent updates only from a manifest signed with an offline Ed25519 key; the
public key is baked into the binary at build time. A tampered version
description is rejected - verified on a live stand. The downloaded binary is
checked against the signed hash before it ever lands on disk as executable. The
signing key is kept out of the repository and off the server, so a compromised
panel may serve anything it likes and the node will still install nothing.

That holds for updates. The first install trusts the panel and its TLS: a clean
node has no key to check a signature with yet, and the installer only compares
the binary with the hash the same panel serves.

The agent never moves backwards: only a version strictly newer than the current
one is installed. Otherwise a compromised panel could roll the fleet back to an
old release with a known hole without forging anything - the signature on a past
release is genuine and passes the check. A downgrade stays a human decision:
`sudo sekvyr update --allow-downgrade --restart sekvyr-agent` on that node
(without `--restart` the running service stays on its version until it
restarts).

**What remains.** Compromise of the repository itself or of the build machine.
The project has no defence of its own there beyond reproducible steps and the
signing key being offline.

**And what the agent exists for also remains.** A compromised panel serves
values - that is its job, and the agent's signature has nothing to do with it.
The value reaches the application's environment, and after a change the agent
runs a command from its own local config (usually a container restart). The
command is set by the node, not by the panel, but the application will still
receive the value and act on it. Browser-side encryption is the answer here: in
an e2e project the server only ever sees ciphertext.

## What the system does not have

- No protection against someone who was legitimately granted a value.
- No provable log without an external receiver.
- Browser-side encryption exists but is not the default: in an ordinary project
  the server sees the values while the panel is unsealed. A new, empty project
  can be put into the mode where only the browser holds the key; the price is
  described in [docs/e2e.md](e2e.md).
- No high availability: the panel runs as one process, and the root key lives in
  its memory.
