#!/bin/sh
# Sekvyr: восстановление базы из бэкапа.
#
#   ops/restore.sh backups/sekvyr-20260908-031700.sql.sealed
#
# Что этот скрипт НЕ восстанавливает: корневой ключ. Его в бэкапе нет и быть не
# должно - иначе дамп и ключ ездят вместе, и шифрование базы становится
# украшением. После восстановления панель поднимется запертой и попросит доли
# (или ключ из вашего файла). Если доли потеряны, значения не вернуть ничем -
# на этот случай существует аварийный архив, см. docs/backup.ru.md.
#
# Восстановление затирает текущую базу целиком. Скрипт спрашивает подтверждение
# и перед заливкой снимает дамп того, что было: передумать после `psql` уже
# нельзя, а "я думал, там пусто" случается чаще, чем хотелось бы. Этот дамп
# возвращается этим же скриптом, а заливка идет одной транзакцией: если она
# сорвется, база останется такой, какой была.
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

# Каталог панели нужен еще до справки: язык вывода записан в ее .env.
APP="${SEKVYR_APP:-}"
if [ -z "$APP" ]; then
    APP="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)"
fi
pick_lang

FILE="${1:-}"
HELP_RC=2
case "$FILE" in
    -h|--help) FILE=""; HELP_RC=0 ;;
    -*) msg "неизвестный ключ: $FILE" "unknown option: $FILE" >&2; exit 2 ;;
esac
if [ -z "$FILE" ]; then
    msg "Восстановление базы панели из бэкапа:

  ops/restore.sh backups/sekvyr-20260908-031700.sql.sealed

Текущая база затирается целиком: скрипт спросит подтверждение и сначала снимет
дамп того, что было. Корневого ключа в бэкапе нет, поэтому после восстановления
панель заперта и ждет доли или ключ." "Restore the panel database from a backup:

  ops/restore.sh backups/sekvyr-20260908-031700.sql.sealed

The current database is replaced entirely: the script asks for confirmation and
takes a dump of what was there first. The root key is not in the backup, so
after a restore the panel is sealed and waits for the shares or the key." >&2
    exit "$HELP_RC"
fi
[ -r "$FILE" ] || { msg "файл не читается: $FILE" "cannot read the file: $FILE" >&2; exit 1; }
# Путь проверяется здесь, а читается после cd в каталог установки: относительный
# путь из другого каталога ломался уже после подтверждения.
case "$FILE" in /*) ;; *) FILE="$(pwd)/$FILE" ;; esac

[ -f "$APP/compose.yml" ] || { msg "не найдена установка панели: $APP" "panel installation not found: $APP" >&2; exit 1; }
cd "$APP"
pick_lang

if docker compose ps >/dev/null 2>&1; then DC="docker compose"
elif sudo -n docker compose ps >/dev/null 2>&1; then DC="sudo docker compose"
else msg "docker compose недоступен из-под $(id -un)" "docker compose is not available to $(id -un)" >&2; exit 1; fi

DB_USER="$(grep -E '^SEKVYR_DB_USER=' .env 2>/dev/null | cut -d= -f2-)"
DB_NAME="$(grep -E '^SEKVYR_DB_NAME=' .env 2>/dev/null | cut -d= -f2-)"
[ -n "$DB_USER" ] || DB_USER=sekvyr
[ -n "$DB_NAME" ] || DB_NAME=sekvyr

msg "Восстановить базу «$DB_NAME» из $FILE?" "Restore the database \"$DB_NAME\" from $FILE?"
msg "Текущее содержимое будет затёрто. Введите имя базы для подтверждения: " \
    "The current contents will be overwritten. Type the database name to confirm: " | tr -d '\n'
read -r answer || true
[ "$answer" = "$DB_NAME" ] || { msg "не подтверждено — выходим" "not confirmed, exiting"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# --- распечатываем, если файл запечатан ------------------------------------
if head -c 15 "$FILE" | grep -q '^SEKVYR-SEALED'; then
    # Открываем внутри контейнера панели: там уже есть cryptography, и на хосте
    # ставить ничего не нужно. Пароль и файл идут одним потоком - первой строкой
    # пароль, дальше содержимое. Так он не появляется ни в аргументах команды
    # (их видно в `ps` любому на хосте), ни временным файлом на диске.
    FROM_LABEL="$(msg "файл от" "file from")"
    unseal_with() {
        # Мимо entrypoint образа: его строка в stdout попала бы в начало дампа.
        { printf '%s\n' "$1"; cat "$FILE"; } | $DC run --rm --no-deps -T --entrypoint python backend -c "
import sys
from app import sealedfile
password = sys.stdin.buffer.readline().decode().strip()
head = sealedfile.unseal(sys.stdin.buffer, sys.stdout.buffer, password=password)
print('$FROM_LABEL', head.get('created', '?'), file=sys.stderr)
" > "$WORK/dump.sql"
    }
    ask_password() {
        msg "Пароль файла: " "File password: " | tr -d '\n'
        stty -echo 2>/dev/null || true
        # без "|| true" пароль, поданный в stdin без перевода строки в конце,
        # молча обрывал скрипт: read возвращает ошибку, а set -e выходит
        read -r PASSWORD || true
        stty echo 2>/dev/null || true
        echo ""
    }
    PASSWORD="$(cat "$APP/secret/backup.pass" 2>/dev/null || true)"
    msg "→ распечатываю" "→ unsealing"
    if [ -n "$PASSWORD" ] && unseal_with "$PASSWORD" 2>"$WORK/unseal.log"; then
        cat "$WORK/unseal.log" >&2
    else
        # На новом сервере в secret/backup.pass уже лежит пароль этой установки:
        # quickstart заводит его сразу. А бэкап зашифрован паролем старой.
        [ -n "$PASSWORD" ] && msg "  пароль из secret/backup.pass не подошел - бэкап, видимо, с другой установки" \
            "  the password from secret/backup.pass does not fit: the backup seems to come from another installation"
        ask_password
        unseal_with "$PASSWORD" || {
            msg "✗ файл не распечатался: пароль не тот или файл поврежден" "✗ the file did not open: wrong password or a damaged file" >&2
            exit 1
        }
    fi
else
    cp "$FILE" "$WORK/dump.sql"
fi

# --- страховка -------------------------------------------------------------
SAFETY="$APP/backups/before-restore-$(date -u +%Y%m%d-%H%M%S).sql"
mkdir -p "$APP/backups"
msg "→ снимаю дамп текущей базы: $SAFETY" "→ taking a dump of the current database: $SAFETY"
# --clean --if-exists, как у ops/backup.sh: без них страховочный дамп не
# ложится поверх живой базы, и вернуть его этим же скриптом было нельзя.
( umask 077; $DC exec -T db pg_dump -U "$DB_USER" -d "$DB_NAME" --clean --if-exists > "$SAFETY" ) \
    || { msg "не удалось снять страховочный дамп — восстановление отменено" "could not take the safety dump, the restore is cancelled" >&2; exit 1; }

# --- заливка ---------------------------------------------------------------
# Бэкенд на время заливки останавливаем: миграции и живые запросы к базе,
# которую сейчас пересоздают, дают ошибки, которые потом долго объясняют.
msg "→ останавливаю бэкенд" "→ stopping the backend"
$DC stop backend >/dev/null

msg "→ заливаю дамп" "→ loading the dump"
# Одной транзакцией: дамп сначала удаляет таблицы, и сорвавшаяся на середине
# заливка без нее оставила бы базу наполовину пустой. Схема пересоздается
# целиком: --clean удаляет только то, что есть в дампе, и бэкап, снятый до
# появления новой таблицы, иначе не ложился в базу новой версии.
if ! { printf 'DROP SCHEMA public CASCADE;\nCREATE SCHEMA public;\n'; cat "$WORK/dump.sql"; } \
    | $DC exec -T db psql -v ON_ERROR_STOP=1 --single-transaction -U "$DB_USER" -d "$DB_NAME" >/dev/null; then
    msg "✗ заливка не прошла, база осталась как была. Страховочный дамп: $SAFETY" \
        "✗ the load failed; the database is as it was. Safety dump: $SAFETY" >&2
    $DC start backend >/dev/null 2>&1 || $DC up -d backend >/dev/null
    exit 1
fi

# Сначала start: тот же контейнер, что работал. up -d - только если его нет
# (down, смена образа): на ручной установке без COMPOSE_FILE up по одному
# compose.yml пересобрал бы бэкенд из исходников.
msg "→ поднимаю бэкенд" "→ starting the backend"
$DC start backend >/dev/null 2>&1 || $DC up -d backend >/dev/null

i=0
while [ $i -lt 60 ]; do
    if $DC exec -T backend python -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=3)" \
        </dev/null >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 2
done
if [ $i -ge 60 ]; then
    msg "✗ дамп залит, но панель не ответила за две минуты: $DC logs --tail=80 backend" \
        "✗ the dump is loaded, but the panel did not answer within two minutes: $DC logs --tail=80 backend" >&2
    msg "  Вернуть как было: ops/restore.sh $SAFETY" "  To go back: ops/restore.sh $SAFETY" >&2
    exit 1
fi

echo ""
msg "✓ база восстановлена. Страховочный дамп: $SAFETY" "✓ the database is restored. Safety dump: $SAFETY"
msg "  Вернуть как было: ops/restore.sh $SAFETY" "  To go back: ops/restore.sh $SAFETY"
echo ""
msg "Дальше: панель заперта — откройте сейф долями или корневым ключом (если ключ запомнен на этом сервере файлом, она отопрется сама)." \
    "Next: the panel is sealed. Open the vault with the shares or the root key (if the key is kept on this server in a file, it unseals by itself)."
msg "Корневой ключ в бэкапе не хранится, это не потеря, а замысел." \
    "The root key is not kept in backups: that is by design, not a loss."
