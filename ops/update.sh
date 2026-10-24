#!/bin/sh
# Sekvyr: обновление панели на месте.
#
#   ops/update.sh            обновить до последнего выпуска (или main при сборке)
#   ops/update.sh v1.2.0     обновить до метки
#
# Панель на готовых образах (compose.ghcr.yml в COMPOSE_FILE) обновляется до
# выпуска, а не до main: код рядом и образы должны быть одной версии.
#
# Порядок такой: сначала бэкап, потом обновление. Миграции необратимы, и
# "откатимся, если что" без свежего дампа - это не план, а надежда. Образы
# нового выпуска скачиваются еще раньше бэкапа: не скачались - не меняется
# ничего.
set -eu

# git pull ниже переписывает и этот файл, а sh читает скрипт по ходу
# выполнения: после обновления он дочитал бы уже другой текст со старого места.
# Поэтому работаем из копии, а каталог панели передаем ей явно.
if [ -z "${SEKVYR_UPDATE_COPY:-}" ]; then
    _app="${SEKVYR_APP:-$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)}"
    _copy="$(mktemp)"
    cp "$0" "$_copy"
    SEKVYR_UPDATE_COPY="$_copy" SEKVYR_APP="$_app" exec sh "$_copy" "$@"
fi
trap 'rm -f "$SEKVYR_UPDATE_COPY"' EXIT

# Язык вывода: SEKVYR_LANG из окружения или из .env панели, иначе русская
# локаль, иначе английский.
pick_lang() {
    L="${SEKVYR_LANG:-}"
    if [ -z "$L" ] && [ -n "${APP:-}" ] && [ -r "${APP:-}/.env" ]; then
        L="$(grep -m1 '^SEKVYR_LANG=' "$APP/.env" | cut -d= -f2- | tr -d "\"' ")"
    fi
    case "$L" in
        ru|en) ;;
        *) case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in ru*) L=ru ;; *) L=en ;; esac ;;
    esac
}
# msg "по-русски" "in English"
msg() { if [ "$L" = ru ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }
pick_lang

REF="${1:-}"
APP="${SEKVYR_APP:-}"
if [ -z "$APP" ]; then
    APP="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)"
fi
pick_lang
# Разбираем аргумент до всего остального: --help, ушедший в git checkout и в
# SEKVYR_IMAGE_TAG, сломал бы .env, причем уже после бэкапа.
case "$REF" in
    -h|--help)
        msg "Обновление панели на месте, с бэкапом перед миграциями:

  ops/update.sh            до последнего выпуска (или main при сборке)
  ops/update.sh v1.2.0     до метки" "Upgrade the panel in place, with a backup before the migrations:

  ops/update.sh            to the latest release (or main when building)
  ops/update.sh v1.2.0     to a tag"
        exit 0 ;;
    -*) msg "неизвестный ключ: $REF" "unknown option: $REF" >&2; exit 2 ;;
esac
[ -f "$APP/compose.yml" ] || { msg "не найдена установка панели: $APP" "panel installation not found: $APP" >&2; exit 1; }
cd "$APP"
pick_lang

# .env закрыт правами 0600, каталог панели и git принадлежат его владельцу
# (обычно root). Без доступа скрипт ошибался молча и посреди работы: не
# прочитав .env, он принимал панель на готовых образах за сборку из исходников,
# а git не мог перейти на новую версию уже после бэкапа.
if { [ -e .env ] && { [ ! -r .env ] || [ ! -w .env ]; }; } || [ ! -w . ]; then
    msg "✗ у $(id -un) нет доступа к $APP/.env или к каталогу панели: запустите скрипт от root (sudo $APP/ops/update.sh${REF:+ $REF})" \
        "✗ $(id -un) has no access to $APP/.env or the panel directory: run the script as root (sudo $APP/ops/update.sh${REF:+ $REF})" >&2
    exit 1
fi

if docker compose ps >/dev/null 2>&1; then DC="docker compose"
elif sudo -n docker compose ps >/dev/null 2>&1; then DC="sudo docker compose"
else msg "docker compose недоступен из-под $(id -un)" "docker compose is not available to $(id -un)" >&2; exit 1; fi

WAS="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"

# Сборка из исходников после "update.sh vX.Y.Z" стоит на теге, а не на ветке, и
# git pull там не работает. Говорим об этом до бэкапа, а не после.
if ! grep -q '^COMPOSE_FILE=.*compose\.ghcr\.yml' .env 2>/dev/null && [ -z "$REF" ] \
    && ! git symbolic-ref -q HEAD >/dev/null 2>&1; then
    msg "✗ установка стоит на теге $(git describe --tags 2>/dev/null || echo '?'), а не на ветке: укажите выпуск явно, например ops/update.sh v1.2.0" \
        "✗ the installation is on tag $(git describe --tags 2>/dev/null || echo '?'), not on a branch: name the release, e.g. ops/update.sh v1.2.0" >&2
    exit 1
fi

GHCR=0
grep -q '^COMPOSE_FILE=.*compose\.ghcr\.yml' .env 2>/dev/null && GHCR=1

# Измененные файлы репозитория сорвали бы checkout и merge уже после бэкапа.
if ! git diff --quiet HEAD -- 2>/dev/null; then
    msg "✗ в каталоге панели изменены файлы из репозитория: $(git diff --name-only HEAD | head -n 3 | tr '\n' ' ')- уберите правки (git stash) и запустите снова" \
        "✗ files from the repository were changed in the panel directory: $(git diff --name-only HEAD | head -n 3 | tr '\n' ' ')- drop the edits (git stash) and run again" >&2
    exit 1
fi

# Обновления забираем до бэкапа: куда идем, надо знать раньше, чем что-то
# менять.
msg "→ забираю обновления" "→ fetching the update"
git fetch --tags --quiet
# Без аргумента в сборке из исходников дальше будет git pull: ветка без
# upstream или разошедшаяся с ним сорвала бы его уже после бэкапа.
if [ "$GHCR" = "0" ] && [ -z "$REF" ]; then
    if ! git rev-parse -q --verify '@{u}' >/dev/null 2>&1; then
        msg "✗ у ветки $(git symbolic-ref -q --short HEAD) нет upstream: укажите ветку или метку явно" \
            "✗ the branch $(git symbolic-ref -q --short HEAD) has no upstream: name a branch or a tag" >&2
        exit 1
    fi
    if ! git merge-base --is-ancestor HEAD '@{u}' 2>/dev/null \
        && ! git merge-base --is-ancestor '@{u}' HEAD 2>/dev/null; then
        msg "✗ ветка разошлась с upstream: сведите их вручную и запустите снова" \
            "✗ the branch has diverged from its upstream: reconcile them by hand and run again" >&2
        exit 1
    fi
fi
ASKED="$REF"
if [ "$GHCR" = "1" ]; then
    REF="${REF:-$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+[.][0-9]+[.][0-9]+$' | head -n 1)}"
    [ -n "$REF" ] || { msg "✗ в репозитории нет ни одного выпуска" "✗ the repository has no releases" >&2; exit 1; }
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

# Назад код не уводим: миграции необратимы, и старый код на новой схеме базы
# не поднимается. Установка на пре-релизе (v1.1.0-rc1) новее последнего
# выпуска, и "обновление" без метки переводило ее на v1.0.x. Сравниваем и
# версии меток (выпуски бывают коммитами без общей истории, и предков у них
# нет), и историю - для веток.
if [ -n "$REF" ]; then
    # Ветку - по origin: локальная после fetch стоит там, где была.
    TARGET="$(git rev-parse -q --verify "origin/$REF^{commit}" 2>/dev/null \
        || git rev-parse -q --verify "$REF^{commit}" 2>/dev/null || true)"
    [ -n "$TARGET" ] || { msg "✗ нет такой метки или ветки: $REF" "✗ no such tag or branch: $REF" >&2; exit 1; }
    CUR="$(git describe --tags --exact-match --match 'v[0-9]*' HEAD 2>/dev/null || true)"
    OLDER=""
    case "$REF" in
        v[0-9]*) [ -n "$CUR" ] && ver_lt "$REF" "$CUR" && OLDER=1 ;;
    esac
    # Локальная ветка впереди origin (свои коммиты на сервере): цель - она
    # сама, иначе "origin позади" выглядел бы откатом. Разошедшиеся локальная
    # и origin - отказ до бэкапа: fast-forward тут невозможен.
    if git show-ref -q --verify "refs/heads/$REF" && git show-ref -q --verify "refs/remotes/origin/$REF"; then
        if git merge-base --is-ancestor "refs/remotes/origin/$REF" "refs/heads/$REF" 2>/dev/null; then
            TARGET="$(git rev-parse "refs/heads/$REF")"
        elif ! git merge-base --is-ancestor "refs/heads/$REF" "refs/remotes/origin/$REF" 2>/dev/null; then
            msg "✗ ветка $REF разошлась с origin/$REF: сведите их вручную и запустите снова" \
                "✗ the branch $REF has diverged from origin/$REF: reconcile them by hand and run again" >&2
            exit 1
        fi
    fi
    # По истории - для всех: и метка, и ветка, оказавшиеся позади
    # установленного кода, увели бы его назад под уже переведенной базой.
    if [ "$TARGET" != "$(git rev-parse HEAD)" ] && git merge-base --is-ancestor "$TARGET" HEAD 2>/dev/null; then
        OLDER=1
    fi
    if [ -n "$OLDER" ]; then
        if [ -z "$ASKED" ]; then
            msg "✓ установка ($WAS) новее последнего выпуска $REF - обновлять нечего" \
                "✓ the installation ($WAS) is newer than the latest release $REF, nothing to update"
            exit 0
        fi
        msg "✗ $REF старше установленной версии ($WAS): код назад не переводится, база уже на новой схеме." \
            "✗ $REF is older than the installed version ($WAS): the code is not moved back, the database is already on the new schema." >&2
        msg "  Вернуть прежнее состояние целиком: ops/restore.sh с бэкапом, снятым до обновления." \
            "  To return to the previous state entirely: ops/restore.sh with the backup taken before the update." >&2
        exit 1
    fi
fi

# compose с меткой образов не из .env: переменная окружения перебивает .env.
# sudo окружение сбрасывает, поэтому под ним метка передается через env.
dc_tag() {
    _tag="$1"; shift
    if [ "$DC" = "docker compose" ]; then
        SEKVYR_IMAGE_TAG="$_tag" docker compose "$@"
    else
        sudo env SEKVYR_IMAGE_TAG="$_tag" docker compose "$@"
    fi
}

# Образы новой версии берем до бэкапа и до checkout. Раньше их скачивал up,
# когда код уже стоял на новой метке, а в .env был новый SEKVYR_IMAGE_TAG:
# без доступа к ghcr.io или с выпуском, который CI еще собирает, обновление
# обрывалось на полпути, и следующий же docker compose up искал образы,
# которых нет. Теперь такой сбой не меняет ничего.
OLD_TAG=""
NEW_TAG=""
if [ "$GHCR" = "1" ]; then
    OLD_TAG="$(grep -m1 '^SEKVYR_IMAGE_TAG=' .env | cut -d= -f2-)"
    NEW_TAG="${REF#v}"
    msg "→ беру образы $REF" "→ pulling the $REF images"
    if ! dc_tag "$NEW_TAG" pull backend frontend; then
        msg "✗ образы $REF не скачались. Ничего не изменено: панель работает на прежней версии ($WAS)." \
            "✗ the $REF images could not be pulled. Nothing was changed: the panel runs the previous version ($WAS)." >&2
        msg "  Проверьте, что сервер достает до ghcr.io. Образы нового выпуска появляются там через несколько минут после метки." \
            "  Check that the server reaches ghcr.io. The images of a new release appear there a few minutes after its tag." >&2
        exit 1
    fi
fi

msg "→ бэкап перед обновлением" "→ backup before the update"
[ -x ops/backup.sh ] || {
    msg "  ops/backup.sh не найден — обновление отменено" "  ops/backup.sh not found, the update is cancelled" >&2
    exit 1
}
# 75 - идет другой бэкап (ночной по расписанию). Ждем его и делаем свой:
# миграциям нужен дамп, снятый прямо перед ними.
tries=0
while :; do
    rc=0
    SEKVYR_APP="$APP" ops/backup.sh || rc=$?
    [ "$rc" = "0" ] && break
    if [ "$rc" = "75" ] && [ $tries -lt 60 ]; then
        [ $tries = 0 ] && msg "  идет другой бэкап, жду его окончания" "  another backup is running, waiting for it to finish"
        tries=$((tries + 1))
        sleep 10
        continue
    fi
    msg "✗ бэкап не сделан — обновление отменено" "✗ the backup failed, the update is cancelled" >&2
    exit 1
done

if [ "$GHCR" = "1" ]; then
    git checkout --quiet "$REF"
    if grep -q '^SEKVYR_IMAGE_TAG=' .env; then
        sed -i "s|^SEKVYR_IMAGE_TAG=.*|SEKVYR_IMAGE_TAG=${REF#v}|" .env
    else
        printf 'SEKVYR_IMAGE_TAG=%s\n' "${REF#v}" >> .env
    fi
elif [ -n "$REF" ]; then
    git checkout --quiet "$REF"
    # Ветка: подтянуть до origin, иначе "update.sh main" оставлял отставшую
    # локальную main как есть. Без pull: у ветки без upstream он падал уже
    # после бэкапа.
    if git symbolic-ref -q HEAD >/dev/null 2>&1 \
        && git show-ref -q --verify "refs/remotes/origin/$REF"; then
        git merge --ff-only --quiet "origin/$REF"
    fi
else
    git pull --ff-only --quiet
fi
NOW="$(git rev-parse --short HEAD)"
# Та же версия - это и тот же код, и та же метка образов: на готовых образах
# код мог уже стоять на выпуске, а .env отставать.
SAME=0
[ "$WAS" = "$NOW" ] && [ "$OLD_TAG" = "$NEW_TAG" ] && SAME=1
[ "$SAME" = "1" ] && msg "  версия та же ($NOW)" "  same version ($NOW)"

# Без COMPOSE_FILE compose берет один compose.yml. Если панель стоит за caddy
# (оверлей compose.caddy.yml), такое обновление пересоздало бы фронтенд без
# меток и сети caddy, и панель пропала бы снаружи. Ручная установка эту строку
# не пишет, поэтому смотрим на работающий фронтенд и дописываем ее сами.
if ! grep -q '^COMPOSE_FILE=' .env 2>/dev/null && [ -f compose.caddy.yml ]; then
    FRONT="$($DC ps -q frontend 2>/dev/null || true)"
    if [ -n "$FRONT" ] && ${DC% compose} inspect --format '{{index .Config.Labels "caddy"}}' "$FRONT" 2>/dev/null | grep -q .; then
        if [ -w .env ]; then
            printf 'COMPOSE_FILE=compose.yml:compose.caddy.yml\n' >> .env
            msg "  панель стоит за caddy, а в .env не было COMPOSE_FILE - дописал" \
                "  the panel is behind caddy and .env had no COMPOSE_FILE: added it"
        else
            msg "✗ панель стоит за caddy, а в .env нет строки COMPOSE_FILE=compose.yml:compose.caddy.yml." \
                "✗ the panel is behind caddy, but .env has no COMPOSE_FILE=compose.yml:compose.caddy.yml line." >&2
            msg "  Без нее обновление снимет панель с caddy. Допишите ее и запустите снова." \
                "  Without it the update would take the panel off caddy. Add it and run again." >&2
            exit 1
        fi
    fi
fi

if [ "$GHCR" = "1" ]; then
    msg "→ поднимаю $REF" "→ starting $REF"
    $DC up -d --pull missing
else
    msg "→ собираю и поднимаю" "→ building and starting"
    $DC up -d --build
fi

msg "→ жду ответа панели" "→ waiting for the panel to answer"
i=0
while [ $i -lt 90 ]; do
    if $DC exec -T backend python -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=3)" \
        </dev/null >/dev/null 2>&1; then
        echo ""
        $DC exec -T backend python -c \
            "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/api/health').read().decode())" \
            </dev/null
        if [ "$SAME" = "1" ]; then
            msg "✓ версия прежняя ($NOW), панель отвечает" "✓ the version is unchanged ($NOW), the panel answers"
        elif [ "$WAS" = "$NOW" ]; then
            msg "✓ образы приведены к $REF (были ${OLD_TAG:-latest})" "✓ the images now match $REF (they were ${OLD_TAG:-latest})"
        else
            msg "✓ обновлено: $WAS → $NOW" "✓ updated: $WAS → $NOW"
        fi
        exit 0
    fi
    i=$((i + 1))
    sleep 2
done

msg "✗ панель не ответила за три минуты. Журнал: $DC logs --tail=80 backend" \
    "✗ the panel did not answer within three minutes. Log: $DC logs --tail=80 backend" >&2
exit 1
