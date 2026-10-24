# Migrating from Infisical and Vault

[Русская версия](migrate.ru.md)

Moving a secrets vault is done once and nobody wants to do it twice. So it works
in two steps: first the panel shows what it sees on the other side and what
happens to each key, and only then it migrates.

By default existing values are not touched at all. Someone else's set of keys on
top of a working environment is the fastest way to break production quietly.

## What the other side needs

**Infisical.** A machine identity (Universal Auth) allowed to read the project:
its id and secret. The panel can list the projects that identity can see - the
"Find projects" button. It needs the right to read values: without it Infisical
returns a placeholder instead of the value, and the panel does not migrate such
a key but shows it as skipped. The panel asks `/api/v4/secrets`, and
`/api/v3/secrets/raw` on a self-hosted Infisical that does not have it yet.

**Vault.** A token allowed to read a KV v2 subtree and to `LIST` its metadata.
The mount and the path are given separately.

Credentials live in the open tab and only travel with the request. The panel does
not store them: it must not become a second place holding access to your old
vault. Which is also why preview and migration each fetch from the source anew.

## How the structure maps

**Infisical.** The secret path maps one to one: `/` stays at the root, `/infra`
becomes the folder `/infra` inside the chosen panel folder.

The environment's imports are migrated with it, into the folder that was read,
and become ordinary keys. They merge the way the Infisical CLI merges them: a key
of the environment itself wins over an imported one with the same name, and of
two imports the later one wins. References to other keys (`${KEY}`) are
expanded: what gets migrated is the value the application sees.

**Vault.** A Vault secret is a set of pairs, usually the variables of one
application. Its fields become the keys, and the path of the secret from the
starting point becomes the folder: the secret at the starting point itself lands
in the chosen panel folder, `<path>/db` lands in the folder `/db`. For example,
`secret/myapp/prod` with the fields `DB_URL` and `API_KEY`, migrated with the
path `myapp/prod`, gives `DB_URL` and `API_KEY` at the root of the environment.
The path may point at a folder or at a single secret. Values that are not
strings (numbers, flags, objects) arrive as JSON.

## What the preview shows

For each key, what will happen: **create**, **update** or **identical**. Values
do not reach the preview, only their length: it must not become a way to look at
someone else's secrets around the read permission.

Two more answers:

- **skip** - the migration will not write this key, and the reason is next to
  it: an invalid name or folder, or the source did not return the value. The
  preview checks what the migration checks and does not promise "create" where
  the migration would skip.
- **write** - you may write into the folder but cannot see its keys. In that
  case the panel does not say whether a key with this name is there: otherwise
  the preview would answer that around the restriction.

The summary at the top answers the main question of a migration: how many keys
arrive new and how many are already there.

## Migrating

The "Migrate" button. Without the "overwrite existing values" checkbox the keys
already present stay as they are and land in the skipped list. With it they are
updated, and each change becomes an ordinary new version: the history is visible
and rollback works.

A key whose value matches what is already stored creates no version at all and
is not reported as skipped: "forty skipped" about identical values alarms exactly
where nothing happened. The history should show changes, not the fact that a
migration was run.

The audit log gets one `secrets_migrated` entry: from where, how many created,
updated and skipped. No values there.

## Permissions

The migration page is for maintainers and above: it calls external systems with
credentials typed into it, which is an administrator's job. On top of that the
`write` right is checked as for any edit, in the target environment and in every
folder the keys land in. The preview requires the same as the migration: for a
folder you may not write into it answers 403, not a list of that folder's keys.
There is no separate migration right, since this is ordinary writing of values,
just a lot of them at once.

## Caveats

- The panel calls the address it was given, internal ones included: self-hosted
  Infisical and Vault almost always live inside the perimeter. The "public
  addresses only" check used for webhooks cannot apply here, and that is written
  down in the [threat model](threat-model.md). Only loopback, link-local (cloud
  metadata at 169.254.169.254) and other cloud service addresses are refused: no
  vault lives there. An error shows what the source put into its own error
  fields, never the page it returned.
- Only current values are migrated. Version history, comments and permissions
  stay on the other side - every vault stores them differently, and pretending to
  "migrate everything" would give a plausible but wrong picture.
- Infisical imports are migrated as ordinary keys: they will no longer be
  references. The panel says so, and says how many keys came from imports.
- A key name holds only letters, digits, `_`, a dot and a dash, what docker
  compose can parse. A key with another name (a Vault field `smtp/host`, for
  example) is not migrated: it lands in the skipped list with the reason.
- More than 5000 keys at once is refused - narrow the path. So is a source
  answer larger than 20 MB: the size is checked while reading. An answer in the
  wrong format (a proxy placeholder, another service at that address) gives a
  clear error, not a 500.
