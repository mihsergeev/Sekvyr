#!/bin/sh
# Sekvyr: установка панели на чистый сервер одной командой.
#
#   curl -fsSL https://raw.githubusercontent.com/mihsergeev/Sekvyr/main/ops/quickstart-ru.sh | sudo sh
#
# Что делает: ставит Docker (если его нет), поднимает caddy-docker-proxy для
# TLS, клонирует репозиторий, генерирует секреты, запускает панель из готовых
# образов выпуска (с --build и не на amd64 собирает из исходников), заводит
# ночные шифрованные бэкапы и сторожа вне контейнеров, а в конце печатает адрес
# и пароль владельца.
#
# Домен по умолчанию - <публичный-IP>.sslip.io: этот DNS отвечает адресом,
# записанным в самом имени, поэтому Let's Encrypt выдает для него обычный
# сертификат. Для постоянной установки укажите свой домен:
#   ... | sudo sh -s -- --domain sekvyr.example.ru --allow-ips "203.0.113.10"
#
# Ключи:
#   --domain <имя>       домен вместо <IP>.sslip.io
#   --allow-ips "A B"    адреса, которым открыта АДМИНКА (машинный контур
#                        остается открытым всем - в этом весь замысел)
#   --timezone <зона>    зона времени панели (по умолчанию UTC)
#   --dir <путь>         каталог установки (по умолчанию /opt/sekvyr)
#   --build              собрать образы из исходников, а не брать выпущенные
#                        под amd64 (несколько минут, около 2 ГБ памяти)
#   --no-cron            не заводить расписание бэкапов и сторожа
#
# English version: ops/quickstart.sh
set -eu

# Все тело - одна функция, вызванная последней строкой. Под "curl | sh" скрипт
# приходит на stdin, и без этого оболочка выполняла бы его по мере чтения:
# дочерняя команда, читающая stdin (docker compose exec в бэкапе),
# съедала остаток скрипта, и он обрывался синтаксической ошибкой. Так же
# оборванная загрузка выполнилась бы наполовину. Функция читается целиком
# до первого действия.
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

# Справка живет здесь, а не читается из файла: под "curl | sh" файла нет, и в
# $0 лежит просто "sh".
usage() {
    cat <<'USAGE'
Sekvyr: установка панели на чистый сервер одной командой.

  curl -fsSL https://raw.githubusercontent.com/mihsergeev/Sekvyr/main/ops/quickstart-ru.sh | sudo sh -s -- [ключи]

Ключи:
  --domain <имя>       домен вместо <IP>.sslip.io
  --allow-ips "A B"    адреса, которым открыта АДМИНКА (машинный контур
                       остается открытым всем - в этом весь замысел)
  --timezone <зона>    зона времени панели (по умолчанию UTC)
  --dir <путь>         каталог установки (по умолчанию /opt/sekvyr)
  --build              собрать образы из исходников, а не брать выпущенные
                       под amd64 (несколько минут, около 2 ГБ памяти)
  --no-cron            не заводить расписание бэкапов и сторожа
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
        *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = "0" ] || { echo "Запускайте от root (sudo)." >&2; exit 1; }

say() { printf '\n\033[1m→ %s\033[0m\n' "$*"; }
die() { printf '\n\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

case "$DIR" in
    /*) ;;
    *) DIR="$(pwd 2>/dev/null || echo /root)/$DIR" ;;
esac
DIR="$(printf '%s' "$DIR" | sed 's:/*$::')"
[ -n "$DIR" ] || DIR=/
cd / || die "не удалось перейти в /"

# -- 1. Порты ----------------------------------------------------------------
# Caddy нужны 80 и 443 для сертификата. Проверяем ДО установки чего-либо: на
# машине, которая не может держать панель, не должен остаться лишний Docker.
for port in 80 443; do
    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port\$"; then
        { command -v docker >/dev/null 2>&1 &&
          docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$port->"; } ||
            die "порт $port занят другим процессом — освободите и запустите снова"
    fi
done

# -- 2. Docker ---------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    say "Docker уже стоит: $(docker --version)"
else
    say "Ставлю Docker"
    curl -fsSL https://get.docker.com | sh >/dev/null || die "не удалось поставить Docker"
fi
docker compose version >/dev/null 2>&1 || die "нужен Docker Compose v2 (плагин compose)"

# -- 2b. Панель, поставленная в другой каталог --------------------------------
# Каталог по умолчанию /opt/sekvyr, но панель может стоять где угодно (--dir
# при первом запуске). Запущенный снова без --dir, скрипт увидел бы пустой
# /opt/sekvyr и поставил вторую панель. docker compose называет проект по
# каталогу, поэтому второй "sekvyr" забрал бы работающие контейнеры себе с
# пустой базой, а расписание бэкапов переехало бы на новую установку. Данные
# остаются на диске, но отвечает пустая панель. Поэтому существующая установка
# ищется до того, как что-то тронуто: по меткам compose у контейнера бэкенда и
# по расписанию бэкапов.
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
            die "панель Sekvyr уже стоит в $OTHER_DIR. Чтобы обновить ее, запустите эту команду с --dir $OTHER_DIR. Вторая панель рядом ставится с --dir в свой каталог"
        fi
        NEW_NAME="$(compose_name "$DIR")"
        if printf '%s\n' "$ELSEWHERE" | cut -d'|' -f1 | grep -qxF "$NEW_NAME"; then
            die "панель в $OTHER_DIR работает как проект docker compose $NEW_NAME, и у $DIR то же имя: запуск здесь заменил бы ее контейнеры. Выберите каталог с другим именем"
        fi
        say "В $OTHER_DIR стоит другая панель: ставлю вторую в $DIR"
    fi
fi

# -- 3. Домен ----------------------------------------------------------------
# То, что просили в командной строке: при повторном запуске главнее .env, и о
# расхождении надо сказать прямо, а не печатать его как новый адрес.
DOMAIN_ARG="$DOMAIN"
ALLOW_ARG="$ALLOW_IPS"
FRESH=1
ADMIN_PW=""
if [ -z "$DOMAIN" ]; then
    IP=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    [ -n "$IP" ] || IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    [ -n "$IP" ] || die "не удалось определить публичный адрес — задайте --domain"
    DOMAIN="$IP.sslip.io"
    say "Домен не задан, беру $DOMAIN"
else
    say "Домен: $DOMAIN"
fi

# -- 4. Caddy ----------------------------------------------------------------
# Сеть caddy заводится с IPv6. Без него Docker пропускает соединения по IPv6
# через свой прокси, и caddy видит вместо клиента шлюз моста: белый список
# админки не пускает никого, кто пришел по IPv6, а журнал и лимит входа видят у
# всех них один адрес. С IPv6 в сети Docker пробрасывает их через ip6tables, и
# до caddy доходит настоящий адрес. Подсеть IPv6 Docker 27 и новее выбирает сам.
V6_GATEWAY=0
if ! docker network inspect caddy >/dev/null 2>&1; then
    docker network create --ipv6 caddy >/dev/null 2>&1 || {
        docker network create caddy >/dev/null || die "не удалось создать сеть caddy"
        V6_GATEWAY=1
    }
elif [ "$(docker network inspect caddy --format '{{.EnableIPv6}}')" != "true" ]; then
    V6_GATEWAY=1
fi
if docker ps --format '{{.Image}}' | grep -q caddy-docker-proxy; then
    say "caddy-docker-proxy уже работает"
else
    say "Поднимаю caddy-docker-proxy (TLS и сертификаты)"
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
    (cd /srv/caddy && docker compose up -d >/dev/null) || die "caddy не поднялся"
fi

# ver_lt A B: версия A раньше B (v1.2.3, v1.2.3-rc1). Пре-релиз раньше выпуска
# той же базы; sort -V сам ставил бы 1.1.0 раньше 1.1.0-rc1.
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

# -- 4b. Бэкап перед повторным запуском --------------------------------------
# Повторный запуск - это обновление: код переходит на последний выпуск (или
# main), а бэкенд при старте переводит базу миграциями. Как и ops/update.sh,
# он начинается с бэкапа, и без бэкапа ничего не меняется.
# База поднимается и при остановленной панели (stop, down): данные в ней есть,
# а обновление без бэкапа - ровно то, чего быть не должно. Пустой базе (первый
# запуск оборвался до миграций) бэкап не нужен, а ее дамп backup.sh отвергает
# как слишком маленький, поэтому она пропускается.
BACKUP_PRE=0
if [ -f "$DIR/.env" ] && [ -x "$DIR/ops/backup.sh" ] && command -v docker >/dev/null 2>&1; then
    (cd "$DIR" && docker compose up -d db >/dev/null 2>&1 </dev/null) || true
    i=0
    until (cd "$DIR" && docker compose exec -T db sh -c 'pg_isready -q -U "$POSTGRES_USER"' </dev/null >/dev/null 2>&1); do
        i=$((i + 1))
        [ $i -ge 45 ] && die "база не отвечает, бэкап перед обновлением не сделан, ничего не изменено: смотрите docker compose logs db в $DIR"
        sleep 2
    done
    MIGRATED=$(cd "$DIR" && echo "SELECT count(*) FROM pg_tables WHERE tablename = 'alembic_version';" \
        | docker compose exec -T db sh -c 'psql -tA -U "$POSTGRES_USER" -d "$POSTGRES_DB"' 2>/dev/null | tr -d '[:space:]')
    if [ "$MIGRATED" = "1" ]; then
        say "Бэкап перед обновлением"
        [ -s "$DIR/secret/backup.pass" ] || BACKUP_PRE=1
        tries=0
        while :; do
            rc=0
            # </dev/null: под "curl | sh" сам скрипт идет по stdin.
            (cd "$DIR" && SEKVYR_APP="$DIR" ops/backup.sh </dev/null) || rc=$?
            [ "$rc" = "0" ] && break
            # 75 - идет ночной бэкап: ждем его и делаем свой.
            if [ "$rc" = "75" ] && [ $tries -lt 60 ]; then
                tries=$((tries + 1))
                sleep 10
                continue
            fi
            die "бэкап не сделан, ничего не изменено: запустите $DIR/ops/backup.sh, чтобы увидеть причину"
        done
    else
        say "База пустая (панель еще не запускалась): бэкапить нечего"
    fi
fi

# -- 5. Репозиторий ----------------------------------------------------------
if [ -d "$DIR/.git" ]; then
    say "Обновляю $DIR"
    git -C "$DIR" fetch -q --tags origin || die "git fetch не прошел"
elif [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
    die "каталог $DIR не пуст и это не репозиторий Sekvyr"
else
    say "Клонирую в $DIR"
    command -v git >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq git) >/dev/null 2>&1
    # Клонируем рядом и переносим готовое: клон, оборванный на середине, иначе
    # оставляет непустой каталог без .git, после чего повтор невозможен - ни
    # клонировать (занято), ни обновить (не репозиторий).
    rm -rf "$DIR.tmp"
    git clone -q "$REPO" "$DIR.tmp" || { rm -rf "$DIR.tmp"; die "не удалось клонировать $REPO"; }
    rm -rf "$DIR"
    mkdir -p "$(dirname "$DIR")"
    mv "$DIR.tmp" "$DIR"
fi
cd "$DIR"

# Повторный запуск сохраняет способ установки. Перевод сборки из исходников
# на готовые образы увел бы код с main обратно на последний тег, под базой,
# которую main мог уже перевести на новую схему.
# Без строки COMPOSE_FILE - ручная установка: один compose.yml собирает из
# исходников, если только SEKVYR_IMAGE_TAG не говорит, что она на образах.
if [ "$BUILD" = "0" ] && [ -f .env ] && ! grep -q '^COMPOSE_FILE=.*compose\.ghcr\.yml' .env \
    && { grep -q '^COMPOSE_FILE=' .env || ! grep -q '^SEKVYR_IMAGE_TAG=' .env; }; then
    say "Эта панель собрана из исходников: так и оставляю (явно - флагом --build)"
    BUILD=1
fi

# Выпущенные образы панели собраны под amd64. На любой другой архитектуре
# панель собирается из исходников: тот же код, на несколько минут дольше.
if [ "$BUILD" = "0" ]; then
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) say "Готовых образов под $(uname -m) нет, собираю из исходников"; BUILD=1 ;;
    esac
fi

# Выпущенные образы и код рядом с ними должны быть одной версии: compose-файлы,
# миграции и скрипты берутся из репозитория, сама панель - из образа. Поэтому
# репозиторий переключается на последний выпуск. Сборка из исходников берет
# ветку main как есть.
if [ "$BUILD" = "0" ]; then
    TAG="$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+[.][0-9]+[.][0-9]+$' | head -n 1)"
    if [ -z "$TAG" ]; then
        say "Выпусков в репозитории еще нет, собираю из исходников"
        BUILD=1
    else
        # Повторный запуск установки на пре-релизе (v1.1.0-rc1) там и
        # остается: последний выпуск старше, а код назад под уже переведенной
        # базой ломает панель. Только для уже стоящей установки (.env есть) и
        # только если метка - и правда другой коммит: свежий клон main с меткой
        # rc на конце получает выпуск.
        CUR="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null || true)"
        if [ -f .env ] && [ -n "$CUR" ] \
            && [ "$(git rev-parse "$CUR^{commit}")" != "$(git rev-parse "$TAG^{commit}")" ] \
            && ver_lt "$TAG" "$CUR"; then
            say "Установка на $CUR, это новее последнего выпуска $TAG: так и оставляю"
            TAG="$CUR"
        else
            git checkout -q "$TAG" || die "не удалось переключиться на $TAG"
            say "Выпуск $TAG"
        fi
    fi
fi
if [ "$BUILD" = "1" ]; then
    git checkout -q main 2>/dev/null || true
    git pull -q --ff-only || die "git pull не прошел"
fi

# Сборке из исходников нужно около 2 ГБ: с меньшим объемом ее посреди
# останавливает OOM, а ошибка ничего не говорит о памяти.
if [ "$BUILD" = "1" ]; then
    MEM_MB=$(awk '/^(MemTotal|SwapTotal):/ {s += $2} END {print int(s / 1024)}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "${MEM_MB:-0}" -gt 0 ] && [ "$MEM_MB" -lt 1900 ]; then
        say "ВНИМАНИЕ: сборке из исходников нужно около 2 ГБ памяти, а здесь ${MEM_MB} МБ вместе со swap: сборку может остановить OOM. Добавьте swap или возьмите сервер побольше"
    fi
fi

# -- 6. Настройки ------------------------------------------------------------
if [ "$BUILD" = "1" ]; then
    COMPOSE_LIST="compose.yml:compose.caddy.yml"
else
    COMPOSE_LIST="compose.yml:compose.ghcr.yml:compose.caddy.yml"
fi
FILES=$(printf -- '-f %s ' $(echo "$COMPOSE_LIST" | tr ':' ' '))

if [ -f .env ]; then
    say ".env уже есть — оставляю как есть"
    FRESH=0
    ENV_DOMAIN=$(grep '^SEKVYR_DOMAIN=' .env | cut -d= -f2- | tr -d '"')
    ENV_ALLOW=$(grep '^SEKVYR_ALLOW_IPS=' .env | cut -d= -f2- | tr -d '"')
    if [ -n "$DOMAIN_ARG" ] && [ "$DOMAIN_ARG" != "$ENV_DOMAIN" ]; then
        say "--domain не применен: в .env остался $ENV_DOMAIN. Чтобы перенести панель, поправьте SEKVYR_DOMAIN и SEKVYR_PANEL_URL в $DIR/.env и выполните docker compose up -d"
    fi
    if [ -n "$ALLOW_ARG" ] && [ "$ALLOW_ARG" != "$ENV_ALLOW" ]; then
        say "--allow-ips не применен: в .env остался прежний список. Поправьте SEKVYR_ALLOW_IPS в $DIR/.env и выполните docker compose up -d frontend"
    fi
    ENV_TZ=$(grep '^SEKVYR_TIMEZONE=' .env | cut -d= -f2- | tr -d '"')
    if [ -n "$TZ_ARG" ] && [ "$TZ_ARG" != "$ENV_TZ" ]; then
        say "--timezone не применен: в .env остался $ENV_TZ. Поправьте SEKVYR_TIMEZONE в $DIR/.env и выполните docker compose up -d"
    fi
    DOMAIN="$ENV_DOMAIN"
    ALLOW_IPS="$ENV_ALLOW"
else
    say "Пишу .env со случайными секретами"
    # Файл пишется рядом и встает на место целиком: прогон, оборванный на
    # середине (нет openssl, Ctrl-C), оставлял .env с пустыми секретами, и
    # следующий принимал его за готовый.
    cp .env.example .env.new
    # Права сразу, до первого секрета: sed -i их сохраняет, а окно, когда пароли
    # лежат с правами по umask, на общей машине кто-нибудь да застанет.
    chmod 600 .env.new
    # Пока прогон не дошел до итогового экрана, пароль владельца считается
    # непоказанным: иначе первый прогон, вставший на скачивании образов,
    # оставил бы панель, пароль от которой никому не показали.
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
    set_env SEKVYR_LANG ru
    # Здесь перед бэкендом ДВА прокси (caddy и nginx фронтенда). При неверном
    # числе в журнал и в лимитер входа попадет адрес прокси, и все клиенты
    # схлопнутся в один ключ.
    set_env SEKVYR_TRUSTED_PROXY_HOPS 2
    set_env SEKVYR_BACKUP_STATE_FILE /data/backup.json
    mv .env.new .env
fi

if grep -q '^COMPOSE_FILE=' .env; then
    # Свои оверлеи (install.md советует дописывать их сюда) остаются в конце
    # списка: скрипт заменяет только свои файлы. Кавычки и комментарий в конце
    # строки - не имена файлов; файл, которого уже нет, ломал бы любой вызов
    # docker compose, поэтому он убирается.
    OLD_LIST=$(grep -m1 '^COMPOSE_FILE=' .env | cut -d= -f2- | sed -e 's/[[:space:]][[:space:]]*#.*$//' | tr -d "\"'")
    for f in $(echo "$OLD_LIST" | tr ':' ' '); do
        case "${f#./}" in
            compose.yml|compose.ghcr.yml|compose.caddy.yml) ;;
            *)
                if [ -f "$f" ]; then
                    COMPOSE_LIST="$COMPOSE_LIST:$f"
                else
                    say "COMPOSE_FILE: файла $f нет, он убран из списка"
                fi ;;
        esac
    done
    FILES=$(printf -- '-f %s ' $(echo "$COMPOSE_LIST" | tr ':' ' '))
    sed -i "s|^COMPOSE_FILE=.*|COMPOSE_FILE=$COMPOSE_LIST|" .env
else
    printf 'COMPOSE_FILE=%s\n' "$COMPOSE_LIST" >> .env
fi
# Образы того же выпуска, на котором стоит репозиторий.
if [ "$BUILD" = "1" ]; then
    # Тег образа от прошлой попытки на образах сборке не нужен.
    sed -i '/^SEKVYR_IMAGE_TAG=/d' .env
fi
if [ "$BUILD" = "0" ]; then
    if grep -q '^SEKVYR_IMAGE_TAG=' .env; then
        sed -i "s|^SEKVYR_IMAGE_TAG=.*|SEKVYR_IMAGE_TAG=${TAG#v}|" .env
    else
        printf 'SEKVYR_IMAGE_TAG=%s\n' "${TAG#v}" >> .env
    fi
fi

# -- 7. Запуск ---------------------------------------------------------------
if [ "$BUILD" = "1" ]; then
    say "Собираю образы (несколько минут, нужно около 2 ГБ памяти)"
    docker compose $FILES up -d --build || die "сборка не прошла"
else
    say "Беру выпущенные образы"
    # --pull missing, а не always: тег версии не меняется, и образ, который уже
    # лежит на диске, ровно тот, что нужен.
    docker compose $FILES up -d --pull missing ||
        die "панель не поднялась. Если не скачались образы, запустите ту же команду с --build: панель соберется здесь из исходников"
fi

say "Жду ответа панели"
# Спрашиваем ИЗНУТРИ: снаружи мы приходили бы с адреса самого сервера, которого
# нет в белом списке, и проверка всегда сообщала бы о неудаче при работающей
# панели.
#
# </dev/null обязателен: при запуске "curl | sh" текст скрипта приходит на
# стандартный ввод, а `docker compose exec` съел бы непрочитанный остаток.
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

# -- 8. Обслуживание ---------------------------------------------------------
# Бэкапы и сторож ставятся сразу, а не "потом": потом не наступает, а панель с
# чужими секретами без бэкапов хуже, чем её отсутствие. Расписание запускает
# скрипты прямо из каталога панели: обновление панели обновляет и их, второй
# копии, которая устареет, нет.
BACKUP_NEW=$BACKUP_PRE
[ -s "$DIR/secret/backup.pass" ] || BACKUP_NEW=1
# Обычные файлы расписания может занимать другая панель (вторая, поставленная
# с --dir): ее бэкапы не должны остановиться оттого, что эта заняла имена.
CRON_NAME=sekvyr
OLD_CRON_DIR="$(sed -n 's|^.* root \(/[^ ]*\)/ops/backup\.sh.*$|\1|p' /etc/cron.d/sekvyr-backup 2>/dev/null | head -n 1)"
if [ -n "$OLD_CRON_DIR" ] && [ "$OLD_CRON_DIR" != "$DIR" ] && [ -f "$OLD_CRON_DIR/.env" ]; then
    CRON_NAME="sekvyr-$(compose_name "$DIR")"
fi
if [ "$CRON" = "1" ] && [ -d /etc/cron.d ]; then
    say "Ставлю ночные бэкапы и сторожа"
    printf '17 3 * * * root %s/ops/backup.sh\n' "$DIR" > "/etc/cron.d/$CRON_NAME-backup"
    printf '*/5 * * * * root %s/ops/panel-watchdog.sh\n' "$DIR" > "/etc/cron.d/$CRON_NAME-watchdog"
    chmod 644 "/etc/cron.d/$CRON_NAME-backup" "/etc/cron.d/$CRON_NAME-watchdog"
    "$DIR/ops/backup.sh" >/dev/null 2>&1 </dev/null || true
fi
if [ "$CRON" = "1" ] && [ ! -d /etc/cron.d ]; then
    say "ВНИМАНИЕ: здесь нет /etc/cron.d, ночные бэкапы и сторож НЕ поставлены в расписание. Запускайте $DIR/ops/backup.sh раз в сутки и $DIR/ops/panel-watchdog.sh раз в 5 минут другим способом"
fi

# Пароли печатаются один раз: пароль владельца при первой установке, которая
# дошла до этого экрана, пароль бэкапов тогда, когда его создал этот запуск
# (первый запуск, упавший раньше, иначе не показал бы ни тот, ни другой).
# Повторному запуску (обновление, лог CI) показывать их незачем, а пароль
# владельца могли давно сменить.
BACKUP_PW=""
[ "$BACKUP_NEW" = "1" ] && [ -s "$DIR/secret/backup.pass" ] && BACKUP_PW=$(cat "$DIR/secret/backup.pass")

printf '\n\033[32m════════════════════════════════════════════════════════\033[0m\n'
if [ "$ready" = "1" ]; then
    printf '  Панель готова:  \033[1mhttps://%s\033[0m\n' "$DOMAIN"
else
    printf '  Контейнеры подняты, но панель пока не отвечает.\n'
    printf '  Адрес: https://%s   Проверить: docker compose logs --tail=50\n' "$DOMAIN"
fi
printf '  Логин:   \033[1m%s\033[0m\n' "admin"
# Шаги для начала нужны новой панели. Повторный запуск - это обновление, и
# совет завести корневой ключ у панели, которая давно работает, только путает.
SHOW_NEXT=0
if [ "$FRESH" = "1" ] || [ -f secret/owner-unshown ]; then
    SHOW_NEXT=1
    [ -n "$ADMIN_PW" ] || ADMIN_PW=$(grep '^SEKVYR_ADMIN_PASSWORD=' .env | cut -d= -f2-)
    printf '  Пароль:  \033[1m%s\033[0m\n' "$ADMIN_PW"
    rm -f secret/owner-unshown
else
    printf '  Пароль:  прежний (начальный - SEKVYR_ADMIN_PASSWORD в %s/.env,\n' "$DIR"
    printf '           пароль бэкапов - в %s/secret/backup.pass)\n' "$DIR"
fi
if [ -n "$BACKUP_PW" ]; then
    printf '\n  Пароль шифрования бэкапов:\n'
    printf '  \033[1m%s\033[0m\n' "$BACKUP_PW"
    printf '  Храните его там же, где доли корневого ключа. Без него бэкап не открыть.\n'
fi
if [ -z "$ALLOW_IPS" ]; then
    printf '\n\033[33m  ВНИМАНИЕ: админка открыта всему интернету (белый список пуст).\n'
    printf '  Для хранилища секретов это не то состояние, в котором стоит жить.\n'
    printf '  Задайте SEKVYR_ALLOW_IPS="ваш.адрес" в %s/.env и выполните\n' "$DIR"
    printf '    docker compose up -d frontend\033[0m\n'
fi
if [ "$V6_GATEWAY" = "1" ] && ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
    printf '\n\033[33m  ВНИМАНИЕ: у сервера есть публичный IPv6, а у сети caddy IPv6 нет.\n'
    printf '  Клиенты по IPv6 приходят к caddy с адреса шлюза Docker, и белый\n'
    printf '  список их не пускает. Сеть уже есть, поэтому пересоздается вместе со\n'
    printf '  всем, что к ней подключено:\n'
    printf '    docker network inspect caddy --format "{{range .Containers}}{{.Name}} {{end}}"\n'
    printf '    (остановите эти стеки: docker compose down в каждом, в том числе в %s)\n' "$DIR"
    printf '    docker network rm caddy && docker network create --ipv6 caddy\n'
    printf '    (и снова docker compose up -d в каждом)\n'
    printf '  Docker до 27 нужна еще подсеть: --subnet fd00:cad::/64.\n'
    printf '  Или публикуйте caddy только на IPv4.\033[0m\n'
fi
printf '\033[32m════════════════════════════════════════════════════════\033[0m\n\n'
if [ "$SHOW_NEXT" = "0" ]; then
    printf 'Панель обновлена: данные, ключи и настройки прежние.\n'
    printf 'Если сейф открывается долями или своим ключом, откройте его в "Сейфе":\n'
    printf 'после перезапуска панель ждет запертой.\n\n'
    return 0
fi
printf 'Дальше по порядку:\n'
printf '  1. Войдите, смените пароль, включите второй фактор.\n'
printf '  2. Откройте «Сейф» и заведите корневой ключ. До этого панель заперта\n'
printf '     и ничего не хранит: доли показываются один раз и больше никогда.\n'
printf '  3. Откройте «Обслуживание» и настройте оповещения — панель с секретами\n'
printf '     не должна ломаться молча.\n'
printf '  4. Добавьте первый сервер на странице «Серверы»: там будет готовая\n'
printf '     команда установки агента.\n\n'
}

main "$@"
