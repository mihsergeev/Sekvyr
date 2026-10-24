# A Docker app with `.env` from the panel

[Русская версия](app-docker.ru.md)

The task is simple: an application on a server runs through `docker compose`, and
its variables live in the panel. You edit a value in the web UI and the container
picks it up on its own, without anyone logging into the server.

Below is a step-by-step walkthrough, exactly as verified on a live server.

## What you end up with

```
panel  --HTTPS-->  agent on the server  -->  /run/sekvyr/shop.env  -->  docker compose
                        |                                                 ^
                        +-- after a change it runs -----------------------+
                                   docker compose up -d
```

The values file lives in `tmpfs` (`/run`): it survives agent restarts and
updates, but not a reboot or a stop of the service. The only copy on disk is the
agent's own, encrypted with the node key (see below). The agent asks the panel
once a minute.

There is **one** agent per server, however many applications it serves. The
applications are a list in its config; the agent re-reads that list every minute,
so adding one restarts nothing.

## 1. Create a project and an environment

In the panel: "New project", a name (say `shop`), with a `prod` environment
inside. Then "Add a key" as many times as you need variables.

Multi-line values (configs, keys, certificates) are fine. Values with `$`,
quotes or line breaks are written so that `docker compose` reads them literally
and substitutes nothing inside.

## 2. Connect the server

Servers, "Connect a server", pick the project and then the environment. The
panel shows a single command with a one-time token:

```sh
curl -fsSL https://PANEL/api/v1/machine/install.sh | sudo sh -s -- \
  --token TOKEN --project shop --env prod
```

It does everything at once: downloads the agent into `/opt/sekvyr-agent`,
exchanges the token for a permanent identity (the secret stays on the server
with mode 0600), installs the `sekvyr-agent` service and gives it its first
application.

The token works once and lives fifteen minutes by default; the dialog lets you
set another lifetime.

On a server that is already connected the installer does not spend the token
and only updates the binary: a new identity would leave the old one in the
panel with its permissions, and the applications from `sekvyr add` would drop
out of the list. Grant such a server an environment on its page in the panel,
with "Connect an application". To connect the server again with a new
identity, pass `--reenroll`.

"Without a project" connects just the agent: the command has no `--project`
and `--env`, and applications are added later from the server page.

Installer options worth knowing: `--dir` for another agent directory, and
`--no-cache` if you do not want the encrypted copy of values on disk (a later run
of the installer keeps it; `--cache` turns the copy back on). With `--no-cache`
the agent also deletes a copy left from when it was on.

The installer and the agent speak the language of the panel interface the
command came from: the command carries `--lang`, the unit gets
`Environment=SEKVYR_LANG=<that language>`, and the agent keeps it in its config,
so the service log and `sekvyr add` use it too. `SEKVYR_LANG` set on the server
does not override it: the installer takes `--lang` from the command, and `sudo`
drops `SEKVYR_LANG`, so `sudo sekvyr add` does not see it. To change the
language of the service, run the installer again with `--lang en` or
`--lang ru`: since 1.0.2 it writes the language to the config as well. Only the
commands run by hand: `sudo sekvyr lang en` (without an argument it shows the
current one).

**Behind a proxy.** If the server reaches the outside only through a proxy, run
the installer with `HTTPS_PROXY` (and `NO_PROXY`) in its environment: `sudo -E`
or `export` in a root shell.

```sh
export HTTPS_PROXY=http://proxy.example.com:3128 NO_PROXY=localhost,127.0.0.1
curl -fsSL https://PANEL/api/v1/machine/install.sh | sudo -E sh -s -- \
  --token TOKEN --project shop --env prod
```

The installer saves these values for the service in `/etc/sekvyr/proxy.env`
(mode 0600, the unit reads it through `EnvironmentFile`). To change them later,
edit that file and run `sudo systemctl restart sekvyr-agent`.

**Without systemd** (OpenRC, supervisord, a container) the installer refuses
before connecting, so the token is not spent. Install the agent with
`--no-service` and run `sekvyr agent --config /etc/sekvyr/agent.json` from your
own supervisor. After a self-update outside systemd the agent replaces its own
process with the new binary. If the agent runs in a docker container next to
the application, give that container an init (`init: true` in compose):
otherwise orphaned processes of the commands after a change stay zombies.

## 3. Describe the application

`/app/shop/compose.yml`:

```yaml
services:
  app:
    image: registry.example.com/shop:1.4.2
    restart: unless-stopped
    # The agent writes this file. An absolute path: the file lives in tmpfs
    # rather than in the project directory.
    env_file:
      - /run/sekvyr/shop.env
```

The agent derives the path and the command from the project name and asks
nothing: the file is `/run/sekvyr/shop.env`, and after a change it runs
`docker compose -f /app/shop/compose.yml up -d`. If your compose file lives
elsewhere, say so once:

```sh
sudo sekvyr add shop/prod \
  --on-change 'docker compose -f /srv/shop/docker-compose.yml up -d'
```

Keep the values file in `/run/sekvyr`: the service runs with
`ProtectSystem=strict` and can write only to its own directories. If the file
really has to live elsewhere, allow that directory to the service
(`sudo systemctl edit sekvyr-agent`, then `[Service]` and
`ReadWritePaths=-/srv/shop`; the dash lets the service start when the directory
is missing) and pass `-o /srv/shop/.env` to `sekvyr add`.

The command after a change runs in the same sandbox: the system is read-only
except the directories in `ReadWritePaths`, and home directories are read-only
too (the docker compose plugin and the registry login from `/root/.docker` are
visible). If the command writes somewhere else (`artisan config:cache`, `cp`
into `/srv`), allow that directory the same way with a
`ReadWritePaths=-/path` line.

## 4. Check it

```sh
sudo sekvyr ls                           # which applications are served
sudo cat /run/sekvyr/shop.env            # the values arrived
sudo docker compose -f /app/shop/compose.yml up -d
sudo docker exec shop-app-1 printenv DB_PASSWORD
```

Now change a value in the panel and wait a minute: `sudo journalctl -u
sekvyr-agent -n 5` shows that the values were updated, and right after it
compose recreates the container.

On a live server this took 38 seconds from the edit to a recreated container.

## Another application on the same server

Servers, the "Connect an application" button on the server you need, pick an
environment. The panel grants the server read access and shows the command:

```sh
sudo sekvyr add checkout/prod
```

That is all. No second service appears and there is nothing to restart: the agent
sees the new line in the list within a minute and writes
`/run/sekvyr/checkout.env`.

The button does two things at once, the access policy and the command. The right
used to be granted separately in the Access section, and a forgotten policy met
the agent with "this machine has not been granted the environment".

To drop an application: `sudo sekvyr rm checkout/prod` (the values file and the
agent's copy of this application's values are removed too, so that nothing keeps
running off a stale copy).

The default path comes from the project name. So a second environment of the same
project (stage next to prod) or a project with the same name in another group is
connected with its own file and its own command:

```sh
sudo sekvyr add shop/stage -o /run/sekvyr/shop-stage.env \
  --on-change 'docker compose -f /app/shop-stage/compose.yml up -d'
```

Without `-o` the agent refuses: two applications in one file would overwrite it
every minute. An application from another group is named with its group, the
same way `sekvyr list` shows it: `sudo sekvyr rm initech/frontend/prod`.

The agent keeps the project address together with its group. If a project is
moved to another group, connected servers keep getting it by the old address.
A project with the same name in another group never takes that address over,
though: if the project is deleted or the server's grant runs out, the agent gets
a refusal and leaves the application its last values instead of picking up the
namesake's. Without a group (`sekvyr add frontend/prod`) a project is found only
while its name is unique in the panel.

## Why `up -d` and not `restart`

`docker compose restart` restarts the process inside the **same** container, while
environment variables are baked in when the container is created. Verified: after
an edit, `restart` left the application with the old value, and `up -d` recreated
the container with the new one.

Hence `up -d` by default. Compose does nothing if the file has not changed, so
there are no needless recreations.

## When no restart is needed

Some applications re-read their configuration themselves. Then, instead of
recreating:

```sh
sudo sekvyr add shop/prod \
  --on-change 'docker compose -f /app/shop/compose.yml kill -s HUP app'
```

If the container reads the values file itself, mount a directory, not the file.
The agent replaces the file atomically, and a bind mount of a single file keeps
showing the container the old inode. Give the file its own directory
(`-o /run/sekvyr/shop/app.env`) and mount `/run/sekvyr/shop`.

And if the application reads the file directly, the agent need not touch compose
at all: `--on-change true` only refreshes the file, and the service reloads its
configuration on its own schedule. An empty `--on-change` does not do that: the
agent fills in its default, `docker compose ... up -d`.

`sekvyr add` writes that default into the agent config
(`/etc/sekvyr/agent.json`) when it adds a new application without
`--on-change`. An application whose `on_change` in the config is empty or
missing runs nothing after the file is updated. Earlier versions read an empty
command as `docker compose ... up -d`; now they do not.

Running `add` again for the same application does not create a second entry, it
changes only the flags given this time: the file, the command and the mode set
earlier stay as they were.

A command that failed (docker was restarting, compose broke) is retried until
it passes, even if the values have not changed since: first after a minute,
then with the pause doubling up to an hour. A command changed with
`sekvyr add --on-change` is tried on the next round. The retry survives an
agent restart.

## Worth remembering

- **`env_file` keeps secrets out of `compose.yml`**, and so out of git. Values
  written into `environment:` sit in the compose file in plain text. Inside a
  running container both kinds are ordinary environment variables: anyone who
  can run `docker inspect` on the server sees them.
- **Variables survive a reboot.** Docker bakes them into the container at
  creation, so after a reboot the application comes up with its values even if the
  file is not there yet. Verified: the container restarted without the file and
  kept its variables.
- **You can recreate a container without the panel too.** The agent keeps a copy
  of the last values on disk (`/var/lib/sekvyr/cache*.bin`, encrypted with the
  node key) and unwraps it when the panel is unreachable; its log says so. Only
  when it is unreachable: if access was revoked or the environment is gone, the
  copy is not used. If you do not want a copy on disk, install the agent with
  `--no-cache`: then without the panel no file appears and the container cannot
  be recreated.
- **One server means one identity in the panel and one service**, however many
  applications it serves. The audit log shows which environment the agent
  fetched. The agent asks every minute, but a repeated read of the same values
  is not logged each time: a line appears for a new set of values, a new address,
  and once a day, with the number of repeats since the previous line.
- **The file mode is 0400, owned by root.** docker compose and systemd read it as
  root, so the user your application runs as does not matter. An application
  that reads the file itself under another user cannot; give it the values
  through compose or systemd instead.
- **The file is in the docker compose format, not a shell script.** compose and
  systemd `EnvironmentFile` read it exactly, but do not `source` it in a shell:
  a value holding both an apostrophe and a backtick cannot be written so that
  compose and the shell read it the same way, and the shell would run what is
  between the backticks. To start a process with the values without compose,
  use `sekvyr run -- ./app`. The panel values then override variables of the
  same name inherited from the service or the image.
- **A key name may repeat in different folders.** A server (the agent, ESO,
  `/api/v1/machine/env`) gets one value per name: from the folder that comes
  later in path order (`/db` after `/`). A server granted only one of those
  folders gets the value from it. An `.env` export from the panel for a person
  holds both lines under their folder headers, and the last one wins, as in
  compose.
- **A key name holds only letters (Cyrillic included), digits, `_`, a dot and
  a dash**: what docker compose can parse. A key with an older name (`smtp/host`
  migrated from Vault by early versions, for example) is skipped by the agent
  with a warning and left out of the machine `.env` export. The value under such
  a name cannot be edited: rename the key.
- **Folder rights hold everywhere.** A deny on a folder hides its keys from the
  key list and from what servers get. Actions on a whole environment (export,
  all values at once, restoring a snapshot, changing the environment's parent)
  need the right on every folder of the environment; otherwise the panel
  refuses with 403 and says why.
