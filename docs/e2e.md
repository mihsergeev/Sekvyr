# Browser-side encryption

[Русская версия](e2e.ru.md)

An ordinary project is encrypted by the panel itself: with an environment key
wrapped by the root key. Which has an honest consequence, written down in the
threat model: whoever gets an unsealed panel gets the values.

This mode closes exactly that hole. Values are encrypted in the browser with a
project key the server does not have at all. The panel stores opaque blobs and
cannot open them under any permissions.

## What it costs

Worth understanding before turning it on. The price is not small:

- **A forgotten project password means losing the values.** Nobody can recover
  them: not the panel, not the owner, not a backup.
- **The panel loses everything that needs plaintext**: `.env` export, file
  import, bulk editing, migration from another vault. The emergency archive is
  still built, but such a project is empty in it - with a note saying why.
- **A machine needs the project key.** A human grants it from the browser,
  separately for each machine. Until then the agent gets a refusal with an
  explanation.
- **Only an empty project can be switched.** Otherwise one project would hold
  values of two different kinds.
- **The project password cannot be changed.** There is no such operation in the
  API or the interface: a leaked password means a new project and moving the
  values over. The password is compared byte for byte, so a password pasted in a
  different Unicode normalization (rare, but macOS does it) does not match.

If that is too expensive, the ordinary mode is still there, and it is not bad
either: values in the database are encrypted, and a sealed panel hands them to
nobody.

## How it works

- **The project key** is 32 random bytes, born in the browser and living only in
  the tab.
- **The project password** becomes a wrapping key (PBKDF2-SHA256, 600,000
  iterations) and seals the project key. The panel stores the wrap, the salt and
  a verifier - the browser uses it to tell whether the password is right without
  trying the key on the values.
- **Values** are sealed with AES-256-GCM under the project key and reach the
  server already sealed. The server encrypts them once more with the ordinary
  environment key: the second layer keeps the ciphertext bound to its place and
  keeps the whole versioning machinery working.
- **For a machine** the project key is sealed to its public key. On its first
  request the agent creates an ECDH P-256 pair; the private half stays on the
  node (`/var/lib/sekvyr/node.key`, mode 0600) and the public half arrives with
  the agent's report. The path can be set with `SEKVYR_NODE_KEY`. The browser
  does ECDH with an ephemeral pair, derives the wrapping key with HKDF and
  seals. The panel stores the result.
- **In Kubernetes** all replicas of a pod share one identity, so they need one
  node key: it is created once as a Secret and mounted into the pods, see
  [deploy/kubernetes](../deploy/kubernetes/README.md).

P-256 rather than X25519: it is supported by WebCrypto in every browser and by
the Go standard library the agent is written in. A mode that works in half the
browsers is worse than no mode.

## Turning it on

Project settings -> "Turn on browser-side encryption". The panel asks for the
project password twice and warns about the price. Afterwards:

1. Open an environment - the panel asks for the project password. The key stays
   in this tab until you press "Lock" or close it.
2. Add keys as usual: the browser seals the values itself.
3. Grant machines access, as always: the panel owner in the Access section
   (only the owner sees it), a maintainer with "Connect an application" on the
   server's page.
4. Come back to the project settings and grant each machine the project key. The
   table shows who has it and who does not.

## What the agent sees

If a machine has not been granted the project key, the panel answers with a
clear refusal instead of handing over blobs. Silently writing ciphertext into
the file would be the worst behaviour: the application would come up and behave
strangely.

Changing the node key (a new server, a reinstalled agent) invalidates the old
wraps: they will no longer open, and there is no point in them looking alive.
Grant the key again.

## What the server still sees

Key names, folders, the structure of environments, the version history, who
accessed what and when. The panel sees this in the ordinary mode too: rights,
search and the audit log all work on it. Only the values become a secret - which
is the whole point.

## What it does not protect against

The browser gets the page that does the encryption from the same panel. So the
mode protects against a leaked database or backup, against reading values
through the panel, and against whoever gets an unsealed panel with any rights in
it. Against a takeover of the server itself it protects only until the first
time someone types the password after the takeover: whoever can change the
panel's code or responses can hand the browser a page that captures the project
password, or swap a machine's public key for their own when the key is granted.

What follows from this:

- keep panel updates and access to its server under the same control as the
  secrets themselves;
- if the panel server was taken over, treat the values of the e2e projects whose
  password was typed after that as exposed, and change them;
- a compromised panel cannot read a value, but it can move sealed values between
  keys of one project or bring back an old version: the browser ciphertext is
  not bound to the key name;
- it cannot slip its own values to a node either: the agent remembers that the
  project is encrypted in the browser and with which project key (a mark in
  `/var/lib/sekvyr/`, a fingerprint of the key, not the key; where the disk is
  read-only, as in a pod, the process remembers it until a restart). An answer
  "project not encrypted" or one with another project key is not applied: the
  panel knows the public key of the node and could wrap a key of its own for
  it. If the project really was recreated in the panel, delete the mark by
  hand; the agent names it in the error;
- whoever stole a machine's secret can report their own node key to the panel:
  the project keys granted to the machine are withdrawn, and the next "Grant
  again" would hand the project key to them. The audit log marks such a report
  with "the node key changed": before granting again, make sure the node really
  was reinstalled.
