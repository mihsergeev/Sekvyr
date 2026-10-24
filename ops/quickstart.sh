#!/bin/sh
# Sekvyr: install the panel on a clean server with one command.
#
#   curl -fsSL https://raw.githubusercontent.com/mihsergeev/Sekvyr/main/ops/quickstart.sh | sudo sh
#
# What it does: installs Docker (if missing), brings up caddy-docker-proxy for
# TLS, clones the repository, generates the secrets, starts the panel from the
# released images (or builds it from source with --build and on non-amd64),
# sets up nightly encrypted backups and an out-of-container watchdog, then prints
# the address and the owner password.
#
# The default domain is <public-IP>.sslip.io - a public DNS service that answers
# with the address written in the name itself, so Let's Encrypt issues an
# ordinary certificate for it. For a permanent installation use your own domain:
#   ... | sudo sh -s -- --domain sekvyr.example.com --allow-ips "203.0.113.10"
#
# Options:
#   --domain <name>      domain instead of <IP>.sslip.io
#   --allow-ips "A B"    addresses allowed into the ADMIN UI (the machine API
#                        stays open to everyone - that is the whole design)
#   --timezone <tz>      panel time zone (default UTC)
#   --dir <path>         install directory (default /opt/sekvyr)
#   --build              build the images from source instead of taking the
#                        released amd64 ones (a few minutes, about 2 GB of RAM)
#   --no-cron            do not install backup and watchdog schedules
#
# Русская версия: ops/quickstart-ru.sh
set -eu

# The whole body is one function called on the last line. Under "curl | sh"
# the script arrives on stdin, and without this the shell would run it as it
# reads: a child command that reads stdin (docker compose exec in the backup)
# ate the rest of the script, which then broke off with a syntax error. A cut
# download would likewise run halfway. A function is read in full before
# anything runs.
main() {

DOMAIN=""
ALLOW_IPS=""
TZONE="UTC"
TZ_ARG=""
DIR=/opt/sekvyr
DIR_SET=0
CRON=1
BUILD=0
REPO=https://github.com/mihsergeev/Sekvyr.git

# The help text lives here and is not read back from the file: under
# "curl | sh" there is no file, and $0 is just "sh".
usage() {
    cat <<'USAGE'
Sekvyr: install the panel on a clean server with one command.

  curl -fsSL https://raw.githubusercontent.com/mihsergeev/Sekvyr/main/ops/quickstart.sh | sudo sh -s -- [options]

Options:
  --domain <name>      domain instead of <IP>.sslip.io
  --allow-ips "A B"    addresses allowed into the ADMIN UI (the machine API
                       stays open to everyone - that is the whole design)
  --timezone <tz>      panel time zone (default UTC)
  --dir <path>         install directory (default /opt/sekvyr)
  --build              build the images from source instead of taking the
                       released amd64 ones (a few minutes, about 2 GB of RAM)
  --no-cron            do not install backup and watchdog schedules
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --allow-ips) ALLOW_IPS="$2"; shift 2 ;;
        --timezone) TZONE="$2"; TZ_ARG="$2"; shift 2 ;;
        --dir) DIR="$2"; DIR_SET=1; shift 2 ;;
        --build) BUILD=1; shift ;;
        --no-cron) CRON=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = "0" ] || { echo "Run as root (sudo)." >&2; exit 1; }

say() { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
die() { printf '\n\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

case "$DIR" in
    /*) ;;
    *) DIR="$(pwd 2>/dev/null || echo /root)/$DIR" ;;
esac
DIR="$(printf '%s' "$DIR" | sed 's:/*$::')"
[ -n "$DIR" ] || DIR=/
cd / || die "could not change to /"

# -- 1. Ports ----------------------------------------------------------------
# Caddy needs 80/443 for the certificate. Checked before installing anything:
# a machine that cannot host the panel should not be left with Docker on it.
for port in 80 443; do
    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port\$"; then
        { command -v docker >/dev/null 2>&1 &&
          docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$port->"; } ||
            die "port $port is taken by another process — free it and try again"
    fi
done

# -- 2. Docker ---------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    say "Docker is already installed: $(docker --version)"
else
    say "Installing Docker"
    curl -fsSL https://get.docker.com | sh >/dev/null || die "could not install Docker"
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"

# -- 2b. A panel installed elsewhere ------------------------------------------
# The default directory is /opt/sekvyr, but a panel may live anywhere (--dir
# on the first run). Run again without --dir, this script would see an empty
# /opt/sekvyr and install a second panel. docker compose names a project after
# its directory, so a second "sekvyr" would take over the running containers
# with an empty database, and the backup schedule would move to the new one.
# The data stays on disk, but the panel that answers is empty. So the existing
# installation is looked for before anything is touched: by the compose labels
# of its backend container and by the backup schedule.
compose_name() {
    basename "$1" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-' | sed 's/^[^a-z0-9]*//'
}
installs_elsewhere() {
    {
        docker ps -a --filter label=com.docker.compose.service=backend \
            --format '{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}' \
            2>/dev/null || true
        if [ -f /etc/cron.d/sekvyr-backup ]; then
            sed -n 's|^.* root \(/[^ ]*\)/ops/backup\.sh.*$|-\|\1|p' /etc/cron.d/sekvyr-backup
        fi
    } | while IFS='|' read -r _proj _wd; do
        _wd="$(printf '%s' "$_wd" | sed 's:/*$::')"
        [ -n "$_wd" ] && [ "$_wd" != "$DIR" ] && [ -f "$_wd/.env" ] \
            && [ -f "$_wd/ops/panel-watchdog.sh" ] && printf '%s|%s\n' "$_proj" "$_wd"
    done | sort -u
}
if [ ! -f "$DIR/.env" ]; then
    ELSEWHERE="$(installs_elsewhere)"
    if [ -n "$ELSEWHERE" ]; then
        OTHER_DIR="$(printf '%s\n' "$ELSEWHERE" | head -n 1 | cut -d'|' -f2)"
        if [ "$DIR_SET" = "0" ]; then
            die "a Sekvyr panel is already installed in $OTHER_DIR. To update it, run this command with --dir $OTHER_DIR. A second panel next to it needs --dir with a directory of its own"
        fi
        NEW_NAME="$(compose_name "$DIR")"
        if printf '%s\n' "$ELSEWHERE" | cut -d'|' -f1 | grep -qxF "$NEW_NAME"; then
            die "the panel in $OTHER_DIR runs as the docker compose project $NEW_NAME, and $DIR gives the same name: starting here would replace its containers. Pick a directory with another name"
        fi
        say "Another panel is installed in $OTHER_DIR: installing a second one in $DIR"
    fi
fi

# -- 3. Domain ---------------------------------------------------------------
# What was asked for on the command line: on a repeat run .env wins, and the
# difference has to be said out loud rather than printed as the new address.
DOMAIN_ARG="$DOMAIN"
ALLOW_ARG="$ALLOW_IPS"
FRESH=1
ADMIN_PW=""
if [ -z "$DOMAIN" ]; then
    IP=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    [ -n "$IP" ] || IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    [ -n "$IP" ] || die "could not determine the public IP — pass --domain"
    DOMAIN="$IP.sslip.io"
    say "No domain given, using $DOMAIN"
else
    say "Domain: $DOMAIN"
fi

# -- 4. Caddy ----------------------------------------------------------------
# The caddy network is created with IPv6. Without it Docker passes IPv6
# connections through its own userland proxy, and caddy sees the bridge gateway
# instead of the client: the admin allow-list refuses every IPv6 client, and the
# audit log and the login limiter see one address for all of them. With IPv6 on
# the network Docker forwards them with ip6tables, and the real address reaches
# caddy. Docker 27 and newer picks the IPv6 subnet by itself.
V6_GATEWAY=0
if ! docker network inspect caddy >/dev/null 2>&1; then
    docker network create --ipv6 caddy >/dev/null 2>&1 || {
        docker network create caddy >/dev/null || die "could not create the caddy network"
        V6_GATEWAY=1
    }
elif [ "$(docker network inspect caddy --format '{{.EnableIPv6}}')" != "true" ]; then
    V6_GATEWAY=1
fi
if docker ps --format '{{.Image}}' | grep -q caddy-docker-proxy; then
    say "caddy-docker-proxy is already running"
else
    say "Starting caddy-docker-proxy (TLS and certificates)"
    mkdir -p /srv/caddy
    cat > /srv/caddy/compose.yml <<'YML'
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
    (cd /srv/caddy && docker compose up -d >/dev/null) || die "caddy failed to start"
fi

# ver_lt A B: version A comes before B (v1.2.3, v1.2.3-rc1). A pre-release
# comes before the release of the same base; sort -V alone would put 1.1.0
# before 1.1.0-rc1.
ver_lt() {
    _a="${1#v}"; _b="${2#v}"
    [ "$_a" = "$_b" ] && return 1
    _ab="${_a%%-*}"; _bb="${_b%%-*}"
    if [ "$_ab" = "$_bb" ]; then
        [ "$_a" = "$_ab" ] && return 1
        [ "$_b" = "$_bb" ] && return 0
        [ "$(printf '%s\n%s\n' "$_a" "$_b" | sort -V | head -n 1)" = "$_a" ]
        return
    fi
    [ "$(printf '%s\n%s\n' "$_ab" "$_bb" | sort -V | head -n 1)" = "$_ab" ]
}

# -- 4b. Backup before a rerun ------------------------------------------------
# A rerun is an update: the code moves to the latest release (or main), and
# the backend migrates the database when it starts. Like ops/update.sh, it
# begins with a backup, and without one nothing is changed.
# The database is brought up even when the panel is stopped (stop, down):
# the data is there, and an update without a backup is exactly what must not
# happen. An empty database (a first run that broke off before the
# migrations) has nothing to back up, and backup.sh refuses its dump as too
# small, so it is skipped.
BACKUP_PRE=0
if [ -f "$DIR/.env" ] && [ -x "$DIR/ops/backup.sh" ] && command -v docker >/dev/null 2>&1; then
    (cd "$DIR" && docker compose up -d db >/dev/null 2>&1 </dev/null) || true
    i=0
    until (cd "$DIR" && docker compose exec -T db sh -c 'pg_isready -q -U "$POSTGRES_USER"' </dev/null >/dev/null 2>&1); do
        i=$((i + 1))
        [ $i -ge 45 ] && die "the database does not answer, so there is no backup before the update and nothing was changed: see docker compose logs db in $DIR"
        sleep 2
    done
    MIGRATED=$(cd "$DIR" && echo "SELECT count(*) FROM pg_tables WHERE tablename = 'alembic_version';" \
        | docker compose exec -T db sh -c 'psql -tA -U "$POSTGRES_USER" -d "$POSTGRES_DB"' 2>/dev/null | tr -d '[:space:]')
    if [ "$MIGRATED" = "1" ]; then
        say "Backup before the update"
        [ -s "$DIR/secret/backup.pass" ] || BACKUP_PRE=1
        tries=0
        while :; do
            rc=0
            # </dev/null: under "curl | sh" the script itself arrives on stdin.
            (cd "$DIR" && SEKVYR_APP="$DIR" ops/backup.sh </dev/null) || rc=$?
            [ "$rc" = "0" ] && break
            # 75: the nightly backup is running, wait for it and take our own.
            if [ "$rc" = "75" ] && [ $tries -lt 60 ]; then
                tries=$((tries + 1))
                sleep 10
                continue
            fi
            die "the backup failed, nothing was changed: run $DIR/ops/backup.sh to see why"
        done
    else
        say "The database is empty (the panel has not started yet): nothing to back up"
    fi
fi

# -- 5. Repository -----------------------------------------------------------
if [ -d "$DIR/.git" ]; then
    say "Updating $DIR"
    git -C "$DIR" fetch -q --tags origin || die "git fetch failed"
elif [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
    die "directory $DIR is not empty and is not a Sekvyr repository"
else
    say "Cloning into $DIR"
    command -v git >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq git) >/dev/null 2>&1
    # Clone next to the target and move it into place: a clone interrupted
    # halfway leaves a non-empty directory without .git, and a retry can then
    # neither clone nor pull.
    rm -rf "$DIR.tmp"
    git clone -q "$REPO" "$DIR.tmp" || { rm -rf "$DIR.tmp"; die "could not clone $REPO"; }
    rm -rf "$DIR"
    mkdir -p "$(dirname "$DIR")"
    mv "$DIR.tmp" "$DIR"
fi
cd "$DIR"

# A rerun keeps the way the panel was installed. Switching a source build
# to the released images would move the code from main back to the last tag,
# under a database that main may already have migrated.
# Without a COMPOSE_FILE line it is a manual install: compose.yml alone builds
# from source, unless SEKVYR_IMAGE_TAG says it runs on released images.
if [ "$BUILD" = "0" ] && [ -f .env ] && ! grep -q '^COMPOSE_FILE=.*compose\.ghcr\.yml' .env \
    && { grep -q '^COMPOSE_FILE=' .env || ! grep -q '^SEKVYR_IMAGE_TAG=' .env; }; then
    say "This panel was built from source: keeping that (run with --build anyway to say it explicitly)"
    BUILD=1
fi

# The released panel images are built for amd64. On any other architecture
# the panel is built from source: the same code, a few minutes longer.
if [ "$BUILD" = "0" ]; then
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) say "No released images for $(uname -m), building from source"; BUILD=1 ;;
    esac
fi

# The released images and the code next to them must be of one version: the
# compose files, migrations and scripts come from the repository, the panel
# itself from the image. So the repository is switched to the latest release.
# A build from source takes the main branch as it is.
if [ "$BUILD" = "0" ]; then
    TAG="$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+[.][0-9]+[.][0-9]+$' | head -n 1)"
    if [ -z "$TAG" ]; then
        say "No releases in the repository yet, building from source"
        BUILD=1
    else
        # A rerun of an installation on a pre-release (v1.1.0-rc1) stays
        # there: the latest release is older, and moving the code back under a
        # migrated database breaks the panel. Only for an existing
        # installation (.env is there) and only when the tag is really another
        # commit: a fresh clone of main with an rc tag on its tip gets the
        # release.
        CUR="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null || true)"
        if [ -f .env ] && [ -n "$CUR" ] \
            && [ "$(git rev-parse "$CUR^{commit}")" != "$(git rev-parse "$TAG^{commit}")" ] \
            && ver_lt "$TAG" "$CUR"; then
            say "The installation is on $CUR, newer than the latest release $TAG: keeping it"
            TAG="$CUR"
        else
            git checkout -q "$TAG" || die "could not switch to $TAG"
            say "Release $TAG"
        fi
    fi
fi
if [ "$BUILD" = "1" ]; then
    git checkout -q main 2>/dev/null || true
    git pull -q --ff-only || die "git pull failed"
fi

# A source build needs about 2 GB: with less, the OOM killer stops it halfway
# and the error says nothing about memory.
if [ "$BUILD" = "1" ]; then
    MEM_MB=$(awk '/^(MemTotal|SwapTotal):/ {s += $2} END {print int(s / 1024)}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "${MEM_MB:-0}" -gt 0 ] && [ "$MEM_MB" -lt 1900 ]; then
        say "WARNING: building from source needs about 2 GB of memory, and this server has ${MEM_MB} MB with swap: the build may be killed. Add swap or use a larger server"
    fi
fi

# -- 6. Configuration --------------------------------------------------------
if [ "$BUILD" = "1" ]; then
    COMPOSE_LIST="compose.yml:compose.caddy.yml"
else
    COMPOSE_LIST="compose.yml:compose.ghcr.yml:compose.caddy.yml"
fi
FILES=$(printf -- '-f %s ' $(echo "$COMPOSE_LIST" | tr ':' ' '))

if [ -f .env ]; then
    say ".env already exists — leaving it as is"
    FRESH=0
    ENV_DOMAIN=$(grep '^SEKVYR_DOMAIN=' .env | cut -d= -f2- | tr -d '"')
    ENV_ALLOW=$(grep '^SEKVYR_ALLOW_IPS=' .env | cut -d= -f2- | tr -d '"')
    if [ -n "$DOMAIN_ARG" ] && [ "$DOMAIN_ARG" != "$ENV_DOMAIN" ]; then
        say "--domain is ignored: .env keeps $ENV_DOMAIN. To move the panel, change SEKVYR_DOMAIN and SEKVYR_PANEL_URL in $DIR/.env and run docker compose up -d"
    fi
    if [ -n "$ALLOW_ARG" ] && [ "$ALLOW_ARG" != "$ENV_ALLOW" ]; then
        say "--allow-ips is ignored: .env keeps its own list. Change SEKVYR_ALLOW_IPS in $DIR/.env and run docker compose up -d frontend"
    fi
    ENV_TZ=$(grep '^SEKVYR_TIMEZONE=' .env | cut -d= -f2- | tr -d '"')
    if [ -n "$TZ_ARG" ] && [ "$TZ_ARG" != "$ENV_TZ" ]; then
        say "--timezone is ignored: .env keeps $ENV_TZ. Change SEKVYR_TIMEZONE in $DIR/.env and run docker compose up -d"
    fi
    DOMAIN="$ENV_DOMAIN"
    ALLOW_IPS="$ENV_ALLOW"
else
    say "Writing .env with random secrets"
    # The file is written next to its place and moved in whole: a run cut off
    # halfway (no openssl, Ctrl-C) used to leave an .env with empty secrets
    # that the next run took as finished.
    cp .env.example .env.new
    # The mode goes first, before any secret: sed -i keeps it, while a window
    # with passwords under the umask mode is one someone on a shared host catches.
    chmod 600 .env.new
    # Until a run reaches the final screen, the owner password counts as unseen:
    # a first run that stops at the image download would otherwise leave a
    # panel whose password nobody was ever shown.
    mkdir -p secret && : > secret/owner-unshown
    ADMIN_PW=$(openssl rand -base64 18)
    set_env() { sed -i "s|^$1=.*|$1=$2|" .env.new; }
    set_env SEKVYR_ADMIN_PASSWORD "$ADMIN_PW"
    set_env SEKVYR_JWT_SECRET "$(openssl rand -hex 32)"
    set_env SEKVYR_DB_PASSWORD "$(openssl rand -hex 24)"
    set_env SEKVYR_DOMAIN "$DOMAIN"
    set_env SEKVYR_PANEL_URL "https://$DOMAIN"
    set_env SEKVYR_ALLOW_IPS "$ALLOW_IPS"
    set_env SEKVYR_TIMEZONE "$TZONE"
    set_env SEKVYR_LANG en
    # Two proxies stand in front of the backend here (caddy and the frontend
    # nginx). With the wrong number the audit log and the login limiter see the
    # proxy address instead of the client - every client collapses into one key.
    set_env SEKVYR_TRUSTED_PROXY_HOPS 2
    set_env SEKVYR_BACKUP_STATE_FILE /data/backup.json
    mv .env.new .env
fi

if grep -q '^COMPOSE_FILE=' .env; then
    # Overlays of your own (install.md suggests adding them here) stay at the
    # end of the list: the script replaces only its own files. Quotes and a
    # comment at the end of the line are not file names; a file that is gone
    # would break every docker compose call, so it is left out.
    OLD_LIST=$(grep -m1 '^COMPOSE_FILE=' .env | cut -d= -f2- | sed -e 's/[[:space:]][[:space:]]*#.*$//' | tr -d "\"'")
    for f in $(echo "$OLD_LIST" | tr ':' ' '); do
        case "${f#./}" in
            compose.yml|compose.ghcr.yml|compose.caddy.yml) ;;
            *)
                if [ -f "$f" ]; then
                    COMPOSE_LIST="$COMPOSE_LIST:$f"
                else
                    say "COMPOSE_FILE: $f is not there, left out of the list"
                fi ;;
        esac
    done
    FILES=$(printf -- '-f %s ' $(echo "$COMPOSE_LIST" | tr ':' ' '))
    sed -i "s|^COMPOSE_FILE=.*|COMPOSE_FILE=$COMPOSE_LIST|" .env
else
    printf 'COMPOSE_FILE=%s\n' "$COMPOSE_LIST" >> .env
fi
# The images are of the same release the repository is on.
if [ "$BUILD" = "1" ]; then
    # A build does not need the image tag left by an earlier try on images.
    sed -i '/^SEKVYR_IMAGE_TAG=/d' .env
fi
if [ "$BUILD" = "0" ]; then
    if grep -q '^SEKVYR_IMAGE_TAG=' .env; then
        sed -i "s|^SEKVYR_IMAGE_TAG=.*|SEKVYR_IMAGE_TAG=${TAG#v}|" .env
    else
        printf 'SEKVYR_IMAGE_TAG=%s\n' "${TAG#v}" >> .env
    fi
fi

# -- 7. Start ----------------------------------------------------------------
if [ "$BUILD" = "1" ]; then
    say "Building the images (a few minutes, needs about 2 GB of RAM)"
    docker compose $FILES up -d --build || die "the build failed"
else
    say "Pulling the released images"
    # --pull missing rather than always: a version tag does not change, and an
    # image already on disk is exactly the one needed.
    docker compose $FILES up -d --pull missing ||
        die "the panel did not start. If the images could not be downloaded, run the same command with --build: the panel is then built here from source"
fi

say "Waiting for the panel to answer"
# Ask from the INSIDE: from outside we would connect from the server's own
# address, which the allow-list does not contain, and the check would always
# report failure while the panel works fine.
#
# </dev/null is mandatory: the script itself arrives on stdin under "curl | sh",
# and `docker compose exec` would swallow the unread remainder.
ready=0
i=0
while [ $i -lt 90 ]; do
    if docker compose $FILES exec -T backend \
        python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=3)" \
        </dev/null >/dev/null 2>&1; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 2
done

# -- 8. Maintenance ----------------------------------------------------------
# Backups and the watchdog are installed right away, not "later": later never
# comes, and a panel holding other people's secrets without backups is worse
# than no panel at all. The schedules run the scripts straight from the
# installation: updating the panel updates them too, and there is no second
# copy to go stale.
BACKUP_NEW=$BACKUP_PRE
[ -s "$DIR/secret/backup.pass" ] || BACKUP_NEW=1
# Another panel may own the usual schedule files (a second panel installed
# with --dir): its backups must not stop because this one took the names.
CRON_NAME=sekvyr
OLD_CRON_DIR="$(sed -n 's|^.* root \(/[^ ]*\)/ops/backup\.sh.*$|\1|p' /etc/cron.d/sekvyr-backup 2>/dev/null | head -n 1)"
if [ -n "$OLD_CRON_DIR" ] && [ "$OLD_CRON_DIR" != "$DIR" ] && [ -f "$OLD_CRON_DIR/.env" ]; then
    CRON_NAME="sekvyr-$(compose_name "$DIR")"
fi
if [ "$CRON" = "1" ] && [ -d /etc/cron.d ]; then
    say "Installing nightly backups and the watchdog"
    printf '17 3 * * * root %s/ops/backup.sh\n' "$DIR" > "/etc/cron.d/$CRON_NAME-backup"
    printf '*/5 * * * * root %s/ops/panel-watchdog.sh\n' "$DIR" > "/etc/cron.d/$CRON_NAME-watchdog"
    chmod 644 "/etc/cron.d/$CRON_NAME-backup" "/etc/cron.d/$CRON_NAME-watchdog"
    "$DIR/ops/backup.sh" >/dev/null 2>&1 </dev/null || true
fi
if [ "$CRON" = "1" ] && [ ! -d /etc/cron.d ]; then
    say "WARNING: there is no /etc/cron.d here, so nightly backups and the watchdog are NOT scheduled. Run $DIR/ops/backup.sh daily and $DIR/ops/panel-watchdog.sh every 5 minutes some other way"
fi

# Passwords are printed once: the owner password on the first install that
# reaches this screen, the backup password when this run created it (a first
# run that failed before the backups would otherwise never show either). A
# repeat run (an update, a CI log) has no business showing them again, and the
# owner password may have been changed in the panel long ago.
BACKUP_PW=""
[ "$BACKUP_NEW" = "1" ] && [ -s "$DIR/secret/backup.pass" ] && BACKUP_PW=$(cat "$DIR/secret/backup.pass")

printf '\n\033[32m════════════════════════════════════════════════════════\033[0m\n'
if [ "$ready" = "1" ]; then
    printf '  The panel is ready:  \033[1mhttps://%s\033[0m\n' "$DOMAIN"
else
    printf '  The containers are up, but the panel does not answer yet.\n'
    printf '  Address: https://%s   Check: docker compose logs --tail=50\n' "$DOMAIN"
fi
printf '  Login:     \033[1m%s\033[0m\n' "admin"
# The first steps are for a new panel. A rerun is an update, and advice to
# create the root key for a panel that has been running for months only confuses.
SHOW_NEXT=0
if [ "$FRESH" = "1" ] || [ -f secret/owner-unshown ]; then
    SHOW_NEXT=1
    [ -n "$ADMIN_PW" ] || ADMIN_PW=$(grep '^SEKVYR_ADMIN_PASSWORD=' .env | cut -d= -f2-)
    printf '  Password:  \033[1m%s\033[0m\n' "$ADMIN_PW"
    rm -f secret/owner-unshown
else
    printf '  Password:  as before (the initial one is SEKVYR_ADMIN_PASSWORD in %s/.env,\n' "$DIR"
    printf '             the backup password is in %s/secret/backup.pass)\n' "$DIR"
fi
if [ -n "$BACKUP_PW" ]; then
    printf '\n  Backup password (nightly encrypted dumps):\n'
    printf '  \033[1m%s\033[0m\n' "$BACKUP_PW"
    printf '  Store it where you keep the root-key shares. Without it no backup opens.\n'
fi
if [ -z "$ALLOW_IPS" ]; then
    printf '\n\033[33m  WARNING: the admin UI is open to the whole internet (empty allow-list).\n'
    printf '  For a secrets panel that is not a state to live in. Set\n'
    printf '    SEKVYR_ALLOW_IPS="your.ip" in %s/.env and run\n' "$DIR"
    printf '    docker compose up -d frontend\033[0m\n'
fi
if [ "$V6_GATEWAY" = "1" ] && ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
    printf '\n\033[33m  WARNING: this server has a public IPv6 address, but the caddy network\n'
    printf '  has no IPv6. Clients coming over IPv6 reach caddy as the Docker gateway,\n'
    printf '  and the allow-list refuses them. The network already exists, so it is\n'
    printf '  recreated together with everything attached to it:\n'
    printf '    docker network inspect caddy --format "{{range .Containers}}{{.Name}} {{end}}"\n'
    printf '    (stop those stacks: docker compose down in each, %s among them)\n' "$DIR"
    printf '    docker network rm caddy && docker network create --ipv6 caddy\n'
    printf '    (and docker compose up -d in each again)\n'
    printf '  Docker before 27 also needs a subnet: --subnet fd00:cad::/64.\n'
    printf '  Or publish caddy on IPv4 only.\033[0m\n'
fi
printf '\033[32m════════════════════════════════════════════════════════\033[0m\n\n'
if [ "$SHOW_NEXT" = "0" ]; then
    printf 'The panel is updated: data, keys and settings are as they were.\n'
    printf 'If the vault opens with shares or a key of your own, open it in "Vault":\n'
    printf 'after a restart the panel waits sealed.\n\n'
    return 0
fi
printf 'Next, in this order:\n'
printf '  1. Log in and change the password; enable two-factor authentication.\n'
printf '  2. Open "Vault" and create the root key. Until then the panel is sealed\n'
printf '     and stores nothing: the shares are printed once and never again.\n'
printf '  3. Open "Maintenance" and set up alerts — a secrets panel should not\n'
printf '     fail quietly.\n'
printf '  4. Add your first server on the "Servers" page: it shows the one-line\n'
printf '     install command for the agent.\n\n'
}

main "$@"
