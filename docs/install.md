# Installing and running Sekvyr

[Русская версия](install.ru.md)

## One command

```sh
curl -fsSL https://raw.githubusercontent.com/mihsergeev/Sekvyr/main/ops/quickstart.sh \
  | sudo sh -s -- --domain sekvyr.example.com --allow-ips "203.0.113.10" --timezone Europe/Berlin
```

The script installs Docker if it is missing, brings up `caddy-docker-proxy` for
certificates, clones the repository into `/opt/sekvyr`, generates the secrets,
starts the panel from the released images, sets up nightly encrypted backups
with a watchdog, and prints the address, the login and the password. With
`--build` it builds the images from source instead: a few minutes and about
2 GB of RAM. The released panel images are for amd64, so on other
architectures (arm64 included) the script builds from source by itself.

What it needs: a Linux server with ports 80 and 443 free, and root. Docker is
installed with `get.docker.com`, git with `apt-get` if it is missing; on other
systems install git yourself first.

Without `--domain` it uses `<public-IP>.sslip.io`, a DNS service that answers
with the address written in the name itself, so Let's Encrypt issues an ordinary
certificate and the panel opens over https right away.

`--allow-ips` lists the addresses allowed into the **admin UI**. The machine API
stays open to everyone, and that is the design: servers and clusters pull
secrets from networks that can never be on an administrator's allow-list. An
empty list forbids nobody, and for a secrets panel that is not a state to live
in.

Running it again is an update. Like `ops/update.sh`, the script first takes a
backup of the running panel, and without a successful backup nothing is
changed. Then it moves the code to the latest release (or to the latest `main`
when building from source), and the backend applies the migrations when it
starts. An existing `.env` is not rewritten except the `COMPOSE_FILE` and
`SEKVYR_IMAGE_TAG` lines; overlays of your own in `COMPOSE_FILE` stay at the end
of the list. A rerun does not print the passwords and takes the domain and the
allow-list from `.env` even if the command line says otherwise, and it says so.
Changing the domain or the list means editing `SEKVYR_DOMAIN`,
`SEKVYR_PANEL_URL` and `SEKVYR_ALLOW_IPS` in `.env` and running
`docker compose up -d`.

## What you end up with

| Part | Where | Why |
| --- | --- | --- |
| `db` | internal network | Postgres 18, ciphertext values only |
| `backend` | internal network | the panel API and the machine API |
| `frontend` | behind caddy | static files and security headers |
| `caddy` | 80/443 | TLS, the split between the two APIs, the allow-list |

Data lives in `<install>/data`, the root key, if you keep it on the server, in
`<install>/secret`. Two separate directories on purpose: a database backup must
not carry the key away together with the ciphertext.

The `caddy` network is created with IPv6. Without it Docker passes IPv6
connections through its own proxy, caddy sees the bridge gateway instead of the
client, and the allow-list refuses everyone who comes over IPv6.

## First steps

1. **Change the password and turn on two-factor authentication.** The password
   printed by the installer sits in `.env` in plain text.
2. **Create the vault** in the Vault section. Until then the panel is sealed and
   stores nothing. There are three ways to hold the root key:
   - **Shares** (3 of 5 by default): nobody has the whole key. The shares are
     shown once: hand them to different people and keep them in different
     places. After every restart the panel waits for enough shares.
   - **One key you enter yourself** after every restart. It is not stored on the
     server, so a dump, a backup or a stolen disk is useless without it.
   - **One key on the server**: the panel comes up on its own, and root on the
     host means access to every value. Save the key to
     `<install>/secret/root.key` with mode 0400 and owner 10001, set
     `SEKVYR_ROOT_KEY_FILE=/secret/root.key` in `.env` and run
     `docker compose up -d backend`. Without that the panel comes up sealed
     after a restart.
3. **Set up alerts** in the Maintenance section. The panel reports what cannot
   be learned later: the vault was sealed or opened, sign-in was blocked after a
   burst of attempts, an emergency archive was built, the audit chain no longer
   checks out (the panel recounts it once a day). The same channel carries
   changes to production environments (`SEKVYR_ALERT_ON_ENVS`, `prod production`
   by default), new notes on values, approaching replacement dates, servers that
   stopped pulling secrets, and a weekly digest of changes. None of these
   messages carry values, only the place, the key name and who did it.
4. **Check the backup.** The same section shows when it last ran. The backup
   encryption password is in `<install>/secret/backup.pass`: store it where you
   keep the key shares. Details: [backup.md](backup.md).
5. **Add your first server** on the Servers page: the panel shows the one-line
   agent install command. After the first report you see the system, both
   addresses and the agent version. An outdated agent is highlighted, and it
   updates itself, forwards only: a downgrade takes a human running
   `sudo sekvyr update --allow-downgrade --restart sekvyr-agent` on the node.
   Without `--restart` only the binary on disk changes, and the running service
   stays on its version until it restarts.
6. **Look around a project.** Ctrl+K opens search across the whole panel:
   projects, environments, servers, keys. Project settings hold the required keys
   (the panel shows what is missing in every environment) and the age after which
   a value counts as stale.

## Manual installation

You need Docker with Compose 2.24 or newer and git. Building from source takes
about 2 GB of RAM; the released images do not need it.

### Behind caddy-docker-proxy, as quickstart does it

```sh
# the network caddy watches, with IPv6 (see above);
# Docker before 27 also needs a subnet: --subnet fd00:cad::/64
docker network create --ipv6 caddy

# caddy-docker-proxy itself, unless one is already running on the server
mkdir -p /srv/caddy && cd /srv/caddy
cat > compose.yml <<'YML'
services:
  caddy:
    image: lucaslorentz/caddy-docker-proxy:2.13-alpine
    restart: unless-stopped
    logging:
      driver: json-file
      options: {max-size: "10m", max-file: "3"}
    ports: ["80:80", "443:443"]
    environment:
      CADDY_INGRESS_NETWORKS: caddy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data:/data
    networks: [caddy]
networks:
  caddy:
    external: true
YML
docker compose up -d

# the panel, on a release: the images exist for releases only
git clone https://github.com/mihsergeev/Sekvyr.git /opt/sekvyr
cd /opt/sekvyr
git checkout v1.0.0
cp .env.example .env
chmod 600 .env
$EDITOR .env
docker compose up -d
```

What to set in `.env`:

| Variable | Value |
| --- | --- |
| `SEKVYR_ADMIN_PASSWORD` | the owner password, 12 characters or more |
| `SEKVYR_JWT_SECRET` | `openssl rand -hex 32` |
| `SEKVYR_DB_PASSWORD` | `openssl rand -hex 24` |
| `SEKVYR_DOMAIN` | the panel domain |
| `SEKVYR_PANEL_URL` | the same domain with `https://`: install commands and alert links are built from it |
| `SEKVYR_ALLOW_IPS` | addresses allowed into the admin UI |
| `SEKVYR_TRUSTED_PROXY_HOPS` | `2`: caddy and the frontend nginx |
| `COMPOSE_FILE` | `compose.yml:compose.ghcr.yml:compose.caddy.yml` |
| `SEKVYR_IMAGE_TAG` | `1.0.0`, the release you checked out |

A value with a `$` in it goes in single quotes: docker compose substitutes
`$NAME` in `.env`, and part of an unquoted password would silently disappear.

To build from source, set `COMPOSE_FILE=compose.yml:compose.caddy.yml`, skip
`SEKVYR_IMAGE_TAG` and run `docker compose up -d --build`. `COMPOSE_FILE` matters
in both cases: `ops/update.sh` and any plain `docker compose up` take the file
list from it, and without the caddy overlay the frontend is recreated without
its labels, so the panel disappears from its domain. With `COMPOSE_FILE` set,
docker compose no longer picks up `compose.override.yml` by itself: put your
own overlay into the list.

A build from source checked out on a tag, as above, is not on a branch, so
`ops/update.sh` without an argument refuses: name the release,
`ops/update.sh v1.0.1`.

The panel refuses to start with a weak token-signing secret or the default owner
password. That is not pedantry: with a weak secret anyone could sign themselves
an owner token.

### Behind your own HTTPS proxy

The base `compose.yml` binds the panel to `127.0.0.1:8080`, and HTTPS in front
is yours. Two things to keep in mind:

- `SEKVYR_TRUSTED_PROXY_HOPS` is the number of proxies in front of the backend:
  `2` with your proxy (yours and the frontend nginx), `1` only when nothing
  stands in front, for example behind an SSH tunnel. With a wrong number the
  audit log and the sign-in limiter see a proxy address, every client collapses
  into one key, and one password-guessing run locks everyone out.
- Keep `/api/v1/machine/*` open to your servers and close everything else to
  everyone but the administrators, as `compose.caddy.yml` does.

### Backups and the watchdog

quickstart sets these up; by hand it is two lines:

```sh
echo '17 3 * * * root /opt/sekvyr/ops/backup.sh' > /etc/cron.d/sekvyr-backup
echo '*/5 * * * * root /opt/sekvyr/ops/panel-watchdog.sh' > /etc/cron.d/sekvyr-watchdog
chmod 644 /etc/cron.d/sekvyr-backup /etc/cron.d/sekvyr-watchdog
```

The schedules run the scripts straight from the installation, so an upgrade
updates them too. Settings and a restore: [backup.md](backup.md).

## Upgrading

```sh
ops/update.sh            # to the latest release, or the latest main when building
ops/update.sh v1.2.0     # to a tag
```

A backup is taken first, then the code is updated and the migrations run. If the
backup fails, the upgrade does not start: migrations are irreversible, and
"we'll roll back if anything happens" without a fresh dump is a hope, not a plan.

With the released images the panel moves from release to release: the code next
to it and the images must be of one version, and `ops/update.sh` keeps
`SEKVYR_IMAGE_TAG` in step with the checked-out tag.

The postgres and caddy images are not updated by `ops/update.sh`: their tags are
fixed in compose, and a new database image is a separate decision. Fresh
patches of the same tag arrive with `docker compose pull db` (and `caddy`, if
it comes from this compose) and `docker compose up -d`, after a backup.

## Maintenance scripts

| Script | What it does |
| --- | --- |
| `ops/backup.sh` | dump, encrypt, rotate, mark for the panel, copy offsite |
| `ops/restore.sh` | restore from a backup with a safety dump first |
| `ops/panel-watchdog.sh` | an out-of-container watchdog: silence, a sealed vault, a broken channel |
| `ops/breakglass.py` | emergency access to values without the panel |
| `ops/update.sh` | upgrade with a backup before the migrations |

The scripts and their alerts speak the language of `SEKVYR_LANG` in `.env`
(quickstart sets it to the language of the script that installed the panel),
otherwise that of the locale, English by default.

## Removing a server

On the server itself:

```sh
curl -fsSL https://sekvyr.example.com/api/v1/machine/install.sh | sudo sh -s -- --uninstall
```

The script stops the agent and removes the unit, the binary, the config with
the machine secret, the node key, the encrypted copy of the values and the
files in `/run/sekvyr`. Then delete the server in the panel too (Servers, the
server menu): the machine API cannot delete anything by design, so until then
the machine identity stays valid.

## Your own agent build

The panel serves the agent binary only when its hash matches the signed
`agent/manifest.json`, and agents install an update only when the signature
checks out against the key built into them. A fork that changes the agent signs
its own releases:

```sh
python ops/agent_release.py --keygen      # once: a key pair; keep the private half offline
SEKVYR_AGENT_KEY=... python ops/agent_release.py --sign   # build and sign agent/VERSION
```

Signing builds the agent in the same pinned Go image as the panel image, so the
hashes match what the panel will serve; commit `agent/pubkey.txt` and
`agent/manifest.json`. Agents built with another key do not accept your updates:
reinstall them with the one-line command from the panel.

## When something is off

```sh
docker compose logs --tail=80 backend      # what the panel says
docker compose exec -T backend python -c \
  "import urllib.request;print(urllib.request.urlopen('http://localhost:8000/api/health').read().decode())"
cat data/heartbeat                          # the pulse: time, lock state, alert channel
```

Common cases:

- **The panel answers `sealed`.** The vault is locked: open it with shares or
  the key. After a host reboot this is the normal state unless the key is on the
  server (`SEKVYR_ROOT_KEY_FILE`).
- **No certificate.** Let's Encrypt counts issuances per set of names (five per
  name per 168 hours); repeated reinstalls that delete the caddy directory burn
  through the limit. Check `docker logs <caddy> | grep rateLimited`.
- **No answer from outside, but fine from inside.** You are not on the
  `SEKVYR_ALLOW_IPS` list. The admin UI does not open from the server itself
  either: connections from the host reach caddy through Docker's proxy. To open
  it from the server, tunnel straight to the frontend container:
  `ssh -L 8081:<container address>:8080 <server>`, the address is in
  `docker inspect` of the frontend container.
- **Refused over IPv6 while the address is on the list.** The `caddy` network
  has no IPv6, see "What you end up with". An existing network does not gain
  IPv6, it is recreated together with everything attached to it:
  `docker network inspect caddy` lists the containers; stop their stacks
  (`docker compose down`), run
  `docker network rm caddy && docker network create --ipv6 caddy` (Docker before
  27 also needs a subnet: `--subnet fd00:cad::/64`) and start the stacks again.
  Or publish caddy on IPv4 only.
