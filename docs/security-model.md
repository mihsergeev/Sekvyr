# Sekvyr security model

[Русская версия](security-model.ru.md)

The panel holds other people's passwords, keys and environment variables. One
rule follows from that, and the whole project is built around it: **a
compromised database must not give away values.** Everything else is detail of
how that rule is kept. Who can attack the panel and what stops them is in the
[threat model](threat-model.md).

## Keys and encryption

- A value is encrypted with AES-256-GCM under the key of its environment, and the
  environment key is wrapped with the root key. An environment key is never
  stored or cached in the clear.
- The associated data of the cipher holds the address of the value: environment,
  secret, name and version number, and on reading the key's name and folder are
  checked against the version. A row cannot be moved to another environment, put
  in place of another key or passed off as another version number: the read fails
  instead of returning "some other value". Making an older version current again
  by editing the tables is not caught this way: see the threat model.
- The root key lives only in process memory. All the database keeps of it is a
  check marker, the ciphertext of a known string. Neither the key nor its hash is
  there.
- The panel starts sealed. Until the key is entered, values are available to no
  one, the owner included. Key names stay visible: listing them needs no
  decryption.
- Root key shares: Shamir's scheme over GF(256) with table-free multiplication,
  so an operation takes the same time whatever the data. A share carries a key
  fingerprint and a checksum. Entering the same share twice does not bring the
  threshold closer, and shares of another vault are rejected with a clear
  message.
- Rotation: an environment key is replaced with the whole history re-encrypted,
  the root key by re-wrapping, after which the old shares no longer fit.
- Renaming a key is a new version with re-encryption, not an edit of the row.
  Otherwise a rename could slip someone else's value to the application under the
  name it expects.

### What this gives and what it does not

- A database dump, its backup and a disk image are useless without the root key.
- Root on the host with the panel **sealed** gives nothing either.
- Root on the host with the panel unsealed takes the key from process memory.
  That is the boundary of the scheme, and the only way around it is a mode where
  the server never sees values at all: browser-side encryption, below.
- The root key lives in the memory of one process. That is enough while the
  backend runs as a single container; with several workers each would have to be
  unsealed.

## Sign-in

- Passwords are stored as bcrypt hashes with a minimum length of 12 characters,
  checked both in the API and in the interface; `ops/selfcheck.py` catches any
  drift between the two.
- The sign-in token is a JWT with a lifetime (12 hours by default,
  `SEKVYR_JWT_TTL_MINUTES`) and a version. A password change, a disabled account
  or a role change bumps the version, so tokens issued earlier stop working at
  once rather than when they expire.
- A wrong password and a missing account get the same answer, in the same time:
  the hash is checked even when there is no account. Otherwise guessing names
  would tell who is in the panel.
- The sign-in limit is counted in the database, not in process memory: with
  several workers the threshold would otherwise silently multiply by their
  number. It is counted per address, and for IPv6 per /64 network, since that is
  what a provider gives one subscriber. A successful sign-in does not wipe the
  failures, otherwise someone guessing with an account of their own would mix in
  good sign-ins and never reach the threshold. Failures per account are counted
  too: an account is not locked (anyone outside could then lock the owner out),
  but the owner is told that its password is being guessed.
- A correct password from an address outside the account's allow list gets the
  same refusal as a wrong one, or sign-in would confirm a guessed password.
- Re-entering the password before a dangerous action (changing the password,
  the second factor, the emergency archive) has a limit of its own and leaves a
  trace in the audit log, so a stolen session cannot guess the password there.
- Two-factor authentication uses time-based codes (RFC 6238) with one window of
  tolerance. A used code is not accepted again, or a code seen over someone's
  shoulder would keep working for another half a minute, and two simultaneous
  requests with one code do not both pass. It is turned on with the password and
  a code, and turned off with the password and a code. Both close every other
  session, so a session opened before the factor was on cannot pass permissions
  that require it. The secret goes to the browser once, and the QR code is drawn
  locally, with no outside service.

## Permissions

- Access to secrets is granted by policies, not by roles: to whom, where
  (project, environment, path), what is allowed and until when.
- Closed by default: no policy, no access. The panel owner is the exception, or
  the first action could lock the owner out.
- A deny beats an allow, an expired grant does nothing, and a grant can require
  two-factor authentication to be on. That is a condition of access, not a
  reminder. A refusal under such a grant says so: two-factor is needed, not
  "no right".
- The role sets the hierarchy and the approval threshold, and for a viewer also a
  ceiling: a viewer sees keys and reads values even if a group hands them a write
  permission.
- Accounts are managed by maintainers and above, and only accounts whose role is
  strictly below their own. Likewise only a role strictly below one's own can be
  granted, so nobody can promote themselves or touch an equal. The last active
  owner can be neither disabled nor demoted.
- A disabled account is turned back on only by a role at or above the one that
  disabled it: otherwise a maintainer would bring back someone the owner had
  removed. Accounts disabled before 1.0.1 count as disabled by the owner.
- Setting someone else's password means signing in under that name with all its
  permissions, so it takes being able to do everything that account can, or
  being the owner. Otherwise a maintainer without access to production would
  get there through a developer. Setting someone else's password sends an
  alert, not just a log line.
- Two-factor authentication of another account (someone lost their phone) is
  reset only by the owner and only for a role below the owner. Existing sessions
  end, and the event goes into the log and the alerts. The owner's own second
  factor is reset only by the emergency reset from `.env`.
- Servers are managed by maintainers too, but a maintainer can give a machine
  only an environment they can read themselves, whether by connecting it or with
  a server enrollment token, and for no longer than they can read it: a
  temporary right of the maintainer gives the machine the same expiry. Rotating a machine secret or replacing cluster keys
  requires being able to read everything they open, and so does enabling a
  machine, or changing its addresses or expiry date. Otherwise the role that
  sets up servers would bypass the policies: connect your own machine to someone
  else's environment and read the values through the machine API.
- Machine access rests on people and is checked on every request, not only when
  it is granted. A machine grant works while whoever gave it could still give it
  now: the account is enabled, the role is maintainer or above, and they read
  everything they granted. If whoever created the machine (they hold its
  secret) or, for a pod, whoever created its cluster (they control the cluster
  keys) is disabled or demoted, the machine gets neither a token nor values.
  Otherwise a person who has left would keep reading production through their
  server.
- Disabling an account or demoting it below maintainer tells beforehand how many
  servers and clusters will stop receiving values. The owner, or someone who
  reads everything they receive, can bring them back by taking the server or
  cluster over: from then on the machine and its grants rest on them.
- The same holds for environments: a child serves its parent's values to
  everyone who reads the child, and a copy takes them for good. So a parent can
  be set, and an environment copied, only by someone who reads it in full, every
  folder included, and the environment itself is changed only with the `write`
  right on it.
- `write` without `list` in a folder is a blind write, not a hidden one: from
  the outcome of a write, an import or a migration without overwrite, the
  writer learns whether a key with the name they chose was already there. They
  never see the other names or any values, and since they can already overwrite
  any key whose name they guess, this tells them little more.
- Maintainers and above see the audit log and the account list in full,
  including the names of projects, environments and keys where they hold no
  policy: this is the role that manages accounts and servers, and incidents are
  investigated across the whole panel. The log never holds values.
- The check lives in a single function that every secrets route goes through.
  Two checks make sure it is not forgotten: a static one in CI (a route without
  the guard fails the build) and a live one (`ops/audit_live.py` walks a running
  panel with other people's accounts and tries to get what it should not).

### Approval of changes

- The threshold is set per project (`approval_min_level`) and compared with the
  role level. An edit or a rollback below the threshold (a copy from a
  neighbouring environment and a write into several environments too) creates a
  pending version that is not served until it is approved: applications keep
  reading the previous value all that time.
- What cannot wait for approval is refused below the threshold with 403:
  deleting and renaming a key, import, migration, returning to inheritance,
  restoring a snapshot and changing the parent of an environment. Otherwise
  these would get around the threshold: a new parent changes every inherited
  value at once.
- The approver must rank above the author and must not be the author. Both rules
  are needed: without the first it is a formality between equals, without the
  second an "apply" button.
- The approver must also be at or above the threshold. Otherwise, with the
  threshold at owner, a maintainer would set a developer's password, propose a
  change as that developer and approve it themselves. Rejecting is open below
  the threshold too: a rejection changes no values.
- The author's level is stored with the change when it is proposed. When the
  author is disabled or their role changes, their pending changes are withdrawn:
  rejected, with a log entry. The change was waiting for someone above the old
  role, and approving it against the new one would be a different rule.
- An approved change in a watched environment is alerted the same way as a
  direct one: that is the moment the value in production changes.
- Only the panel owner changes the threshold. Otherwise the person whose edits
  need approval would turn approval off first thing.

## Audit log

- Entries are linked by a hash chain: each keeps the hash of the previous one,
  computed together with its own fields. Editing or deleting a row in the middle
  breaks the chain, and the log check shows where it diverged and how many
  breaks there are.
- Entries are written under a lock, one for the whole panel. Without it two
  concurrent operations would get the same previous hash, the chain would fork,
  and the check would declare the log tampered for no reason. A false alarm
  devalues the real ones.
- Values never reach the log, only the fact of access. Every read of a value by
  a person is its own line. Machines ask the panel every minute, so their reads
  are logged when the set of values is different, the address is new or a day
  has passed since the previous line; repeats in between are counted and land
  in the next line. Refusals are always logged.
- The API has no route that edits or clears the log.
- The chain does not stop someone with database access from cutting the log off
  at the end and writing on. The copy at an outside receiver
  (`SEKVYR_AUDIT_WEBHOOK`) is what covers that: entries go there together with
  their hashes.

## Machine API

- Machines use a separate path, `/api/v1/machine/*`, the only one open to the
  world. The application itself knows which routes are machine routes: a mistake
  in the proxy config must not open the admin UI to everyone.
- It is read-only. It has four routes that change anything, and none of them
  touches values: exchanging a secret for a token, the agent report, revoking
  one's own tokens and enrolling a server with a one-time token. The list is
  fixed in `ops/selfcheck.py`, and a fifth route will not get through CI.
- The permanent machine secret is issued by the panel at enrollment, and the
  database keeps only its hash. The secret is exchanged for an access token that
  lives 15 minutes and is bound to the identity, its address allow-list and the
  secret generation: a new secret kills issued tokens at once.
- A machine token does not open the admin UI, and a machine cannot be granted
  write access: such a policy is rejected on creation.

### The agent on a node

- Enrollment uses a short-lived one-time token. The panel hands the machine
  secret to the agent once, and on the node it sits in the config with mode
  0600. The node itself generates only the key for projects with browser-side
  encryption.
- The first install trusts the panel and its TLS: a clean node has nothing to
  check a signature with yet. The installer compares the downloaded agent with
  the hash in the release description, and from then on the agent updates
  itself only from a description signed with an offline Ed25519 key. The public
  key is built into the binary, the panel does not know the private one, and a
  forged description is rejected: the agent stays on its version and never goes
  back on its own.
- Re-running the installer on a connected node does not download the binary:
  the installed agent replaces it (`sekvyr update`) with the same signature
  check and no rollback. The installer script itself is not covered by the
  signature: it comes from the panel and runs as root. So on a connected node
  the agent is updated with `sudo sekvyr update`, and the script is run for a
  new node or a new unit after reading it.
- The values file is written with mode 0400 and replaced as a whole rather than
  appended to: an application never sees a half-written `.env`. Values in it are
  written so that docker compose and systemd read them literally. It is not a
  shell script: sourced with `. file`, the shell would run substitutions (a
  backtick in a value, for example), so do not source it; `sekvyr run` starts
  a process with the values.
- A copy of the last values for when the panel is unreachable is kept in
  `/var/lib/sekvyr`, encrypted with the node key. Those who do not want it turn
  it off with `--no-cache`, which also deletes a copy left from when it was on.
  `sekvyr rm` removes the copy of that application together with its file.
- The agent service runs with `ProtectSystem=strict`: it can write only to its
  own directories. The command after a change runs within the same limits, and
  home directories are read-only to it.

### Kubernetes

- A pod proves itself with a projected ServiceAccount token, and the signature is
  checked against the cluster keys (JWKS). The panel needs neither credentials
  for the cluster nor access to its API.
- The audience is required: a token issued "for kubernetes" will not do. The
  algorithm comes from the cluster key, not from the token header.
- The signature is checked without asking the cluster, so the panel does not
  see a pod being deleted: its token works until it expires. That is why a token
  living longer than a day is refused: kubelet issues projected tokens for an
  hour and renews them itself, while a year-long `kubectl create token` would be
  a static secret again. One ServiceAccount maps to one machine.
- A cluster identity has no secret at all, so nothing that could be stolen and
  used elsewhere is left in the cluster. Cluster keys are updated in place, and
  pod identities keep their grants.
- Compatibility with External Secrets Operator is kept on purpose and with an
  honest caveat: there a static pair lives in the cluster, because ESO makes a
  single request and cannot exchange a secret for a short-lived token.

## Browser-side encryption

- A project can be switched to a mode where values are encrypted with the project
  key in the browser. The panel stores opaque blobs, has no key, and cannot open
  them with any permissions.
- The project password becomes a wrapping key (PBKDF2-SHA256, 600,000
  iterations). It is checked against a marker, a known string under the project
  key, not by trying to decrypt values.
- For a machine the project key is sealed to its public key (ECDH P-256, HKDF,
  AES-GCM). The private half stays on the node and is never shown to the panel,
  and replacing it kills the old wrappings.
- The panel refuses operations that need plaintext rather than pretending they
  work.
- The browser gets the encrypting page from the same panel, so against a
  takeover of the server the mode helps only until the first time the project
  password is typed after it.
- The price is stated plainly: a forgotten project password means the values are
  gone, with no way back.

## Backups and emergency access

- A database dump is taken on a schedule and encrypted with its own password
  (scrypt and AES-256-GCM, format `SEKVYR-SEALED-1`). The chunk number and the
  last-chunk flag are part of the associated data: a truncated or reshuffled file
  does not open.
- The root key is not in the backup and must not be. A restore is always two
  parts, the dump and the key, kept apart.
- The panel reads the backup script's mark and reports when backups stop. A
  backup that silently stopped is the most common way to end up without one.
- The emergency archive: all values in one sealed file under an archive
  password of its own, 12 characters or more, which the panel does not store.
  Only the owner can build it, with the owner's own password and the second
  factor if the owner has it on. Every build goes to the log and to the alerts.
- `ops/breakglass.py` opens it. It is a standalone file with no imports from the
  panel: in an emergency only Python and `cryptography` are needed. It also gets
  values out of a database dump when the root key or the shares are at hand.
- The panel and the tool must agree on the format, and a test and
  `ops/selfcheck.py` check that they do: they should drift apart on an ordinary
  day, not in an emergency.

## Alerts and the watchdog

- The panel reports sealing and unsealing, sign-in lockouts after a series of
  failures, a built emergency archive, a deleted project and an audit log that no
  longer checks out.
- Addresses the panel calls itself are checked on save: `https` only and public
  addresses only. Otherwise alert settings would turn into requests into the
  internal network. The check runs when an address is saved in the UI; values
  from `.env` are taken as is: they are set by whoever already runs the server.
- Channel settings and the bot token are stored in plain text, in the database
  and in the heartbeat file with mode 0600. That is a deliberate trade: a sealed
  panel cannot decrypt its own token, and that is exactly when it has to say it
  is sealed.
- `ops/panel-watchdog.sh` runs outside the containers and reads the panel's
  heartbeat. It reports when the panel is silent, when it is sealed and when its
  own alert channel is broken, and it gets through even when the panel and the
  database no longer answer. When the problem changes (a sealed panel goes
  silent), it reports again.

## Deployment

- The backend runs as uid 10001, the frontend as an unprivileged nginx on port
  8080, and the containers have `no-new-privileges`. The backend container starts
  as root only to fix the volume owner and drops privileges right away.
- The panel refuses to start with a weak token-signing secret or the default
  owner password.
- The API schema (`/api/openapi.json`) is served only in debug mode.
- The frontend nginx sets the security headers and the CSP. `connect-src 'self'`
  means that even a tampered script cannot send what it read to another address.
- The admin UI is closed by an address allow-list at the edge
  (`compose.caddy.yml`). The Docker subnet is not on it: when the caddy network
  has no IPv6, clients coming over IPv6 arrive through Docker's own proxy, and
  such a list would let all of them in. quickstart creates the caddy network
  with IPv6, so the real address reaches caddy.
- An empty allow-list restricts no one. A panel with secrets should not be left
  that way: set your addresses or keep it behind a VPN.

## Not there yet

- **A Kubernetes operator of its own** with a `SekvyrSecret` resource. Clusters
  currently work through the sidecar agent and External Secrets Operator.
- **Switching an existing project to browser-side encryption.** For now it can
  be turned on only for an empty project: re-encrypting live values in the
  browser is not done yet.
