# Backups, restore and emergency access

[Русская версия](backup.ru.md)

The panel holds other people's secrets, so the question is never "do we have
backups" but "what exactly can we restore, and how fast". There are three
different situations here, and confusing them is expensive.

| What happened | What saves you | What you need at hand |
| --- | --- | --- |
| The panel broke, the database is fine | a restart | nothing |
| The whole server is gone | a database backup plus the root key | the backup file, its password, the key or its shares |
| No panel, no key, production is down | the emergency archive | the archive file and its password |

## The parts

**The database dump.** Taken on a schedule by `ops/backup.sh`. The database
holds ciphertext: without the root key not a single value can be read out of a
dump. The dump is still encrypted with its own password, because it carries
password hashes, machine secret hashes and the whole structure of the vault.

**The root key.** It is not in the backup and must not be: a dump and a key that
travel together turn all the encryption into decoration. Depending on how the
vault was created, the key lives as shares held by different people, as one key
in your password manager, or as a file on the server.

**The emergency archive.** Every value in plain text inside one file sealed with
a password the owner chooses when building it, in the Maintenance section. This
is the only file where all the secrets sit together without the root key, so
treat it as the keys to everything.

## Setting backups up

`ops/quickstart.sh` does it for you. By hand it is two schedules that run the
scripts straight from the installation, so an upgrade updates them too:

```sh
echo '17 3 * * * root /opt/sekvyr/ops/backup.sh' > /etc/cron.d/sekvyr-backup
echo '*/5 * * * * root /opt/sekvyr/ops/panel-watchdog.sh' > /etc/cron.d/sekvyr-watchdog
chmod 644 /etc/cron.d/sekvyr-backup /etc/cron.d/sekvyr-watchdog
```

The first run creates the encryption password in
`<install>/secret/backup.pass` and prints it. **Store it where you keep the root
key shares.** Without it no backup opens, not for you and not for anyone.

If a backup is already running (the nightly one and a manual run at once), the
second run exits with code 75 and does nothing. `ops/update.sh` waits for the
running one to finish and then takes its own.

Settings are lines in the panel's `.env`, or environment variables:

| Variable | Meaning |
| --- | --- |
| `SEKVYR_BACKUP_DIR` | where to put files (default `<install>/backups`) |
| `SEKVYR_BACKUP_KEEP` | how many to keep (default 14) |
| `SEKVYR_BACKUP_OFFSITE` | `user@host:/path`, a copy on another machine over `rsync` |

`SEKVYR_BACKUP_KEEP=0` keeps every backup, and leading zeros do not matter
(`00` is 0 too). A comment at the end of the line in `.env`
(`SEKVYR_BACKUP_KEEP=14  # two weeks`) is cut off, as compose does. A value
that is not a number keeps every backup, and the script warns about it.

The offsite copy matters more than rotation: fire, ransomware and "we deleted
the wrong server" hit the whole host at once, and a backup next to the database
survives none of them.

Every run sends all the backups kept here, so a night when the copy did not go
out is caught up the next night. The script only adds files on the other side
and never deletes anything there, on purpose: a compromised server must not be
able to erase the copies too. Rotation there is the receiving machine's job, so
set it up on that machine, for example with cron:

```sh
echo '30 5 * * * backup find /srv/backups/sekvyr -name "sekvyr-*.sql.sealed" -mtime +30 -delete' \
  > /etc/cron.d/sekvyr-offsite-rotate
```

Keep files there longer than here: a file still kept on the panel server is
sent again on the next run.

The copy goes over SSH as root, because the schedule runs the script as root.
Root needs a key the target accepts and the target's host key in its
`known_hosts`; without them the copy fails at night with "Host key verification
failed" or "Permission denied", and the panel reports the backup as failed:

```sh
sudo ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519   # if root has no key yet
sudo ssh-copy-id -i /root/.ssh/id_ed25519.pub backup@backup.example.com
sudo ssh backup@backup.example.com true                   # accept the host key once
```

The target directory must exist. Only the sealed file travels, so the target
never sees open data.

## How the panel watches the backup

The script leaves a mark in `<install>/data/backup.json`; the panel reads it and
shows it under Maintenance. If the mark is not updated for longer than
`SEKVYR_BACKUP_MAX_AGE_HOURS` (48 by default), the panel says so through the
alerts. Silence is the most common way to end up without backups: they stop
quietly, and it surfaces on the day they are needed.

## Restoring

```sh
cd /opt/sekvyr
sudo ops/restore.sh backups/sekvyr-20260908-031700.sql.sealed
```

The script asks for the database name as confirmation, takes a safety dump of
the current state, stops the backend, loads the dump and brings the panel back.
The load runs in one transaction: if it fails, the database stays as it was. The
safety dump is sealed with the backup password, like the nightly ones, and the
last five are kept. It goes back with the same command:
`sudo ops/restore.sh backups/before-restore-<time>.sql.sealed`.

**On a new server** install the panel first (quickstart is fine), copy the backup
file there and run the same command. The new installation already has its own
password in `secret/backup.pass`, and it does not fit a backup of the old one:
the script notices that and asks for the old password.

After a restore the panel is **sealed**. Open the vault with the shares or the
root key: neither is in the backup, deliberately. If the root key is kept on
this server in a file (`SEKVYR_ROOT_KEY_FILE`), the panel unseals by itself. If
the shares are lost for good, nothing can recover the values from the dump;
that is exactly what the emergency archive is for.

## Emergency access without the panel

`ops/breakglass.py` stands alone: it needs Python and the `cryptography` package
and nothing else. No panel, no network, not even the rest of the repository:
copy the single file.

**From the emergency archive** (the fastest path):

```sh
python3 breakglass.py list sekvyr-emergency-2026-09-08.sealed
python3 breakglass.py env sekvyr-emergency-2026-09-08.sealed acme/web/prod > .env
```

**From a database backup and the root key** (no archive, but a dump exists):

```sh
python3 breakglass.py dump sekvyr-20260908-031700.sql.sealed --list \
    --share 'SEKVYR-1-...' --share 'SEKVYR-1-...' --share 'SEKVYR-1-...'
python3 breakglass.py dump sekvyr-20260908-031700.sql.sealed \
    --env acme/web/prod --key-file root.key > .env
```

The dump is parsed as text, so there is no need to bring up Postgres: in an
emergency "first install a database" costs half an hour and gives you one more
server holding every secret at once.

**Just open a sealed file**:

```sh
python3 breakglass.py open sekvyr-20260908-031700.sql.sealed -o dump.sql
```

## When to build the emergency archive

Maintenance, "Build the archive". The panel asks for the archive password, your
own panel password and, if you have it on, a two-factor code. The event goes
into the audit log and into the alerts, so it cannot be hidden.

A sensible rhythm: after notable changes and before risky work (a migration, a
database upgrade, a root key rotation). Keep it where you keep the shares, and
no longer than it stays true: a stale archive is worse than a missing one,
because it creates a false sense of readiness.

## After a root key rotation

A dump holds the environment keys wrapped by the root key of its time, so a
backup taken before the rotation opens only with the old shares or the old key.
Keep the old shares until the last such backup is rotated out
(`SEKVYR_BACKUP_KEEP` nights, 14 by default, and longer if an offsite copy keeps
them longer), and build a fresh emergency archive right after the rotation.

## Check once a quarter

1. That the latest backup opens: `python3 breakglass.py open <file> -o /tmp/x.sql`.
2. That the shares combine: rebuild the key from enough of them and confirm the
   panel opens with it.
3. That a second person knows where the passwords are and what to do without you.

A backup nobody has ever opened is a hope, not a backup.
