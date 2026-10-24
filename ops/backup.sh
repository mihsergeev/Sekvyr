#!/bin/sh
# Sekvyr: бэкап базы - дамп, шифрование, ротация, отметка для панели.
#
# Что важно понимать про этот бэкап. В базе лежит шифротекст: без корневого
# ключа из дампа не достать ни одного значения. Значит бэкап нужно хранить
# ОТДЕЛЬНО от корневого ключа (и от долей), а восстановление - это всегда две
# части: дамп плюс ключ. Дамп при этом все равно шифруется своим паролем: в нем
# хеши паролей людей, ключи машин и вся структура хранилища.
#
# Расписание запускает скрипт прямо из каталога панели: установку он находит по
# своему месту, а обновление панели обновляет и его. quickstart ставит так:
#   echo '17 3 * * * root /opt/sekvyr/ops/backup.sh' > /etc/cron.d/sekvyr-backup
#   chmod 644 /etc/cron.d/sekvyr-backup
#
# Настройки - строками в .env панели или переменными окружения:
#   SEKVYR_BACKUP_DIR      куда складывать (по умолчанию <установка>/backups)
#   SEKVYR_BACKUP_KEEP     сколько файлов держать (по умолчанию 14)
#   SEKVYR_BACKUP_OFFSITE  "user@host:/path" - куда отправлять копию (rsync)
#   SEKVYR_APP             каталог панели, если скрипт лежит не в ней
#
# Пароль шифрования лежит в <установка>/secret/backup.pass. Если файла нет,
# скрипт создает его сам и печатает: пароль нужно сохранить там же, где доли
# корневого ключа. Без него бэкап не открыть - ни вам, ни кому-либо еще.
set -eu

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

APP="${SEKVYR_APP:-}"
if [ -z "$APP" ]; then
    APP="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)"
fi
[ -f "$APP/compose.yml" ] || { msg "не найдена установка панели: $APP" "panel installation not found: $APP" >&2; exit 1; }

pick_lang

# .env закрыт правами 0600, каталог secret тоже читает только владелец (обычно
# root). Без доступа скрипт молча брал настройки по умолчанию (и копия на
# другую машину выключалась), а пароль шифрования, которого не видно,
# принимал за отсутствующий и пытался завести новый. Оповещения нет: это
# ошибка запуска, а не провал бэкапа.
if { [ -e "$APP/.env" ] && [ ! -r "$APP/.env" ]; } \
    || { [ -d "$APP/secret" ] && [ ! -x "$APP/secret" ]; }; then
    msg "✗ у $(id -un) нет доступа к $APP/.env или $APP/secret: запустите скрипт от root (sudo $APP/ops/backup.sh)" \
        "✗ $(id -un) has no access to $APP/.env or $APP/secret: run the script as root (sudo $APP/ops/backup.sh)" >&2
    exit 1
fi

# Настройка из окружения, а если там пусто - строка из .env панели. .env не
# исполняется: значение берется как есть, без подстановок.
setting() {
    _v="$(printenv "$1" 2>/dev/null || true)"
    if [ -z "$_v" ] && [ -r "$APP/.env" ]; then
        # Комментарий в конце строки (KEEP=14  # две недели) отрезаем, как это
        # делает compose: иначе "14  # ..." не было числом, и ротация молча
        # выключалась.
        _v="$(grep -m1 "^$1=" "$APP/.env" | cut -d= -f2- | sed -e 's/[[:space:]]#.*$//' \
            -e 's/[[:space:]]*$//' -e "s/^['\"]//" -e "s/['\"]\$//")"
    fi
    printf '%s' "${_v:-$2}"
}
DEST="$(setting SEKVYR_BACKUP_DIR "$APP/backups")"
KEEP="$(setting SEKVYR_BACKUP_KEEP 14)"
OFFSITE="$(setting SEKVYR_BACKUP_OFFSITE "")"
PASS_FILE="$APP/secret/backup.pass"
STATE="$APP/data/backup.json"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NAME="sekvyr-$(date -u +%Y%m%d-%H%M%S).sql.sealed"

cd "$APP"

# --- отметка и оповещение --------------------------------------------------
# Оповещать умеем сами, реквизиты берем из пульса панели: если бэкап сломался,
# а панель жива, сообщение уйдет по её же каналу. Если мертва и она - тем более
# нужен независимый путь.
HB="$APP/data/heartbeat"
hb() { grep -m1 "^$1=" "$HB" 2>/dev/null | cut -d= -f2-; }

notify() {
    _msg="$1" _token="$(hb tg_token)" _chat="$(hb tg_chat)"
    _api="$(hb tg_api)"; [ -z "$_api" ] && _api="https://api.telegram.org"
    _hook="$(hb webhook)"
    if [ -n "$_token" ] && [ -n "$_chat" ]; then
        curl -s --max-time 15 "$_api/bot$_token/sendMessage" \
            --data-urlencode "chat_id=$_chat" --data-urlencode "text=$_msg" \
            --data-urlencode "disable_web_page_preview=true" >/dev/null 2>&1 || true
    fi
    [ -n "$_hook" ] && curl -s --max-time 15 -H 'Content-Type: application/json' \
        --data "{\"text\": \"$(printf '%s' "$_msg" | sed 's/\\/\\\\/g; s/"/\\"/g')\"}" \
        "$_hook" >/dev/null 2>&1 || true
}

mark() {
    # Отметку панель читает и показывает в разделе "Обслуживание". Пишем её и
    # при удаче, и при провале: "бэкап не удался" надо видеть так же ясно, как
    # "бэкапа нет вообще". Текст ошибки экранируется: сообщение docker с
    # кавычками ломало JSON, и панель вместо причины писала "отметка не
    # читается".
    _detail="$(printf '%s' "$4" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')"
    mkdir -p "$(dirname "$STATE")"
    printf '{"at": "%s", "ok": %s, "file": "%s", "size": %s, "detail": "%s"}\n' \
        "$STAMP" "$1" "$2" "$3" "$_detail" > "$STATE"
}

fail() {
    echo "✗ $1" >&2
    # Сначала оповещение: если отметку записать не выйдет (кончилось место -
    # частая причина провала бэкапа), о провале все равно узнают.
    notify "$(msg "🔥 Sekvyr: бэкап не сделан — $1" "🔥 Sekvyr: the backup failed: $1")"
    mark false "$NAME" 0 "$1" || true
    exit 1
}

# Docker бывает доступен только под sudo - не угадываем, а проверяем.
if docker compose ps >/dev/null 2>&1; then DC="docker compose"
elif sudo -n docker compose ps >/dev/null 2>&1; then DC="sudo docker compose"
else fail "$(msg "docker compose недоступен из-под $(id -un)" "docker compose is not available to $(id -un)")"; fi

# Два бэкапа разом (cron и ручной запуск) писали в одни и те же файлы ошибок
# и могли оставить испорченный файл с отметкой "ok". Второй выходит с кодом 75
# (EX_TEMPFAIL), а не 0: update.sh по нулю считал, что свежий бэкап есть, и
# шел в миграции без него.
# Каталог, куда нельзя писать (смонтированный диск отвалился, права), - это
# провал с оповещением, а не молчаливый выход по set -e.
mkdir -p "$DEST" 2>/dev/null && [ -w "$DEST" ] ||
    fail "$(msg "в каталог бэкапов нельзя писать: $DEST" "the backup directory is not writable: $DEST")"
if command -v flock >/dev/null 2>&1; then
    exec 9>"$DEST/.backup.lock"
    if ! flock -n 9; then
        msg "бэкап уже идет, этот запуск пропущен" "a backup is already running, this run is skipped" >&2
        exit 75
    fi
fi

# --- пароль ----------------------------------------------------------------
if [ ! -s "$PASS_FILE" ]; then
    mkdir -p "$(dirname "$PASS_FILE")"
    ( umask 077; openssl rand -base64 33 | tr -d '\n' > "$PASS_FILE" )
    chmod 600 "$PASS_FILE"
    # Файл читает контейнер бэкенда, а он работает под uid 10001 и не root.
    # Без смены владельца шифрование падало бы на "Permission denied" - и
    # ровно в ту ночь, когда бэкап делается впервые и никто не смотрит.
    chown 10001:10001 "$PASS_FILE" 2>/dev/null || true
    echo "════════════════════════════════════════════════════════"
    msg "  Создан пароль шифрования бэкапов: $PASS_FILE" "  Created the backup encryption password: $PASS_FILE"
    msg "  СОХРАНИТЕ его там же, где доли корневого ключа." "  SAVE it where you keep the root key shares."
    msg "  Пароль: $(cat "$PASS_FILE")" "  Password: $(cat "$PASS_FILE")"
    msg "  Без него ни один бэкап не открыть." "  Without it no backup can be opened."
    echo "════════════════════════════════════════════════════════"
    # Из cron этот вывод не увидит никто, а все следующие бэкапы зашифрованы
    # этим паролем. Сам пароль в оповещение не идет - только где его взять.
    notify "$(msg "🔑 Sekvyr: создан новый пароль бэкапов, он в $PASS_FILE на сервере. Сохраните его там же, где доли ключа: без него бэкапы не открыть" \
        "🔑 Sekvyr: a new backup password was created, it is in $PASS_FILE on the server. Store it with the key shares: backups cannot be opened without it")"
fi

# --- дамп ------------------------------------------------------------------
DB_USER="$(grep -E '^SEKVYR_DB_USER=' .env 2>/dev/null | cut -d= -f2-)"
DB_NAME="$(grep -E '^SEKVYR_DB_NAME=' .env 2>/dev/null | cut -d= -f2-)"
[ -n "$DB_USER" ] || DB_USER=sekvyr
[ -n "$DB_NAME" ] || DB_NAME=sekvyr

# Дамп шифруется на лету: открытый файл не должен лежать на диске даже секунду.
# Шифрует python напрямую, мимо entrypoint образа: тот пишет в stdout (строка
# попала бы в начало файла бэкапа) и сбрасывает права до uid 10001, которому
# пароль, созданный не им, может быть не прочесть.
# Пароль передается файлом внутри контейнера, а не аргументом: командная строка
# видна в `ps` любому процессу на хосте.
# Код возврата pg_dump сохраняется отдельно: в sh у конвейера код последней
# команды, и дамп, оборвавшийся на середине (перезапуск базы, битая таблица),
# аккуратно запечатывался и считался удачным. Через KEEP таких ночей ротация
# стерла бы последний полный бэкап.
set +e
rm -f "$DEST/.pg_dump.rc"
{
    $DC exec -T db pg_dump -U "$DB_USER" -d "$DB_NAME" --clean --if-exists \
        2>"$DEST/.pg_dump.err"
    echo $? > "$DEST/.pg_dump.rc"
} | $DC run --rm --no-deps -T --entrypoint python backend -m app.cli seal \
        --password-file /secret/backup.pass --note "$(hostname)" \
        > "$DEST/$NAME.part" 2>"$DEST/.seal.err"
STATUS=$?
DUMP_RC="$(cat "$DEST/.pg_dump.rc" 2>/dev/null || echo 1)"
set -e
if [ "$STATUS" != "0" ] || [ "$DUMP_RC" != "0" ]; then
    rm -f "$DEST/$NAME.part" "$DEST/.pg_dump.rc"
    fail "$(tail -c 300 "$DEST/.pg_dump.err" "$DEST/.seal.err" 2>/dev/null | tr '\n' ' ')"
fi
rm -f "$DEST/.pg_dump.rc"

SIZE=$(wc -c < "$DEST/$NAME.part" | tr -d ' ')
# Пустой или подозрительно короткий файл - это провал, который иначе заметят
# через месяц. Заголовок один занимает около трехсот байт.
[ "$SIZE" -gt 4096 ] || fail "$(msg "дамп получился слишком маленьким ($SIZE байт)" "the dump is too small ($SIZE bytes)")"
mv "$DEST/$NAME.part" "$DEST/$NAME"
chmod 600 "$DEST/$NAME"
rm -f "$DEST/.pg_dump.err" "$DEST/.seal.err"

# --- ротация ---------------------------------------------------------------
# Хранятся последние KEEP файлов: место кончается тихо, и первым от этого
# страдает как раз бэкап.
# KEEP=0 или не число - хранить все: "0" читается как "без предела", а
# tail -n +1 стер бы и только что сделанный файл. Ведущие нули убираем: "00"
# не совпадало с "0" и стирало все бэкапы, включая сегодняшний.
case "$KEEP" in
    ''|*[!0-9]*) ;;
    *) KEEP="$(printf '%s' "$KEEP" | sed 's/^0*//')" ;;
esac
case "$KEEP" in
    '') ;;
    *[!0-9]*)
        msg "SEKVYR_BACKUP_KEEP=$KEEP - не число, храню все бэкапы" \
            "SEKVYR_BACKUP_KEEP=$KEEP is not a number, keeping all backups" >&2 ;;
    *)
        # Только что снятый бэкап не трогаем никогда: если часы ушли назад
        # (сброс RTC, ВМ из снимка), у прежних файлов время в будущем, и
        # свежий оказывался последним по списку - ротация стирала его сразу,
        # а отметка говорила "ок".
        ls -1t "$DEST"/sekvyr-*.sql.sealed 2>/dev/null | grep -vxF "$DEST/$NAME" \
            | tail -n +"$KEEP" | while read -r old; do
            rm -f "$old"
        done ;;
esac

# --- офсайт ----------------------------------------------------------------
# Копия на другой машине: пожар, шифровальщик и "удалили не тот сервер" бьют по
# всему хосту сразу, и бэкап рядом с базой от них не спасает.
if [ -n "$OFFSITE" ]; then
    # BatchMode: в cron спросить пароль или подтвердить ключ хоста некому, и
    # ssh должен сразу сказать, чего не хватает. Первая строка ошибки идет в
    # сообщение: "Host key verification failed" или "Permission denied" сразу
    # говорят, что чинить, а голое "не уехала" заставляет гадать.
    #
    # Уходят все бэкапы, что лежат здесь, а не только сегодняшний: rsync
    # пропускает те, что уже на месте, а ночь, когда копия не уехала (сеть,
    # выключенная машина), досылается следующей. Удалять на той стороне скрипт
    # не умеет нарочно: захваченный сервер не должен уметь стереть и копии.
    # Ротация там - дело принимающей машины.
    if ! rsync -a --timeout=120 -e "ssh -o BatchMode=yes -o ConnectTimeout=20" \
            "$DEST"/sekvyr-*.sql.sealed "$OFFSITE/" >/dev/null 2>"$DEST/.rsync.err"; then
        why="$(head -n 1 "$DEST/.rsync.err" | cut -c1-200)"
        rm -f "$DEST/.rsync.err"
        fail "$(msg "копия не уехала на $OFFSITE: $why" "the copy did not reach $OFFSITE: $why")"
    fi
    rm -f "$DEST/.rsync.err"
fi

mark true "$NAME" "$SIZE" ""
msg "✓ $DEST/$NAME ($SIZE байт)" "✓ $DEST/$NAME ($SIZE bytes)"
