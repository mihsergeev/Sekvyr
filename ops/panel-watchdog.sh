#!/bin/sh
# Sekvyr: сторож панели снаружи контейнеров.
#
# Панель не может сообщить о собственной смерти собственным же каналом. Этот
# скрипт читает пульс, который панель пишет раз в минуту в
# <установка>/data/heartbeat (backend/app/heartbeat.py), и НЕЗАВИСИМО шлет
# сообщение, если:
#   - пульса нет или он протух - контейнер или база мертвы;
#   - панель заперта - значения не выдаются никому, включая машины;
#   - сама панель говорит, что её канал оповещений сломан (alerts_ok=0).
# Сменилась проблема (запертая панель замолчала) - сообщает снова.
#
# Реквизиты берет из того же пульса, поэтому достучится и тогда, когда панель с
# базой уже не отвечают.
#
# Расписание запускает скрипт прямо из каталога панели, quickstart ставит так:
#   echo '*/5 * * * * root /opt/sekvyr/ops/panel-watchdog.sh' > /etc/cron.d/sekvyr-watchdog
#   chmod 644 /etc/cron.d/sekvyr-watchdog
set -u

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
HOST_IO="$(dirname "$0")/host-io.sh"
[ -r "$HOST_IO" ] || HOST_IO="$APP/ops/host-io.sh"
. "$HOST_IO"

pick_lang

HB="${SEKVYR_HEARTBEAT:-$APP/data/heartbeat}"
STATE="${SEKVYR_WATCHDOG_STATE:-$APP/data/watchdog.state}"
MAX_AGE="${SEKVYR_HB_MAX_AGE:-600}"
# Проверок подряд с проблемой до тревоги: перезапуск при обновлении не должен
# будить людей, а настоящая поломка живет дольше двух проверок.
STRIKES="${SEKVYR_WD_STRIKES:-2}"
NOW=$(date +%s)

# Пульс - файл 0600 пользователя контейнера, и читается он от root. Без прав на
# него или на свое состояние сторож видел бы "пульса нет" там, где его просто
# не прочесть, и мог позвать людей на ровном месте. Это ошибка запуска, а не
# поломка панели: о ней говорится в вывод, оповещения нет.
_hb_dir="$(dirname "$HB")"
_st_dir="$(dirname "$STATE")"
if { [ -d "$_hb_dir" ] && [ ! -x "$_hb_dir" ]; } \
    || { [ -e "$HB" ] && [ ! -r "$HB" ]; } \
    || { [ -e "$STATE" ] && { [ ! -r "$STATE" ] || [ ! -w "$STATE" ]; }; } \
    || { [ ! -e "$STATE" ] && [ -d "$_st_dir" ] && [ ! -w "$_st_dir" ]; }; then
    msg "сторожу из-под $(id -un) не прочесть пульс $HB или не записать $STATE: запустите его от root (sudo $APP/ops/panel-watchdog.sh)" \
        "the watchdog running as $(id -un) cannot read the heartbeat $HB or write $STATE: run it as root (sudo $APP/ops/panel-watchdog.sh)" >&2
    exit 2
fi

HB_CONTENT=$(read_host_state "$HB") || HB_CONTENT=''
val() { heartbeat_field "$HB_CONTENT" "$1"; }

problem=""
kind=""
if [ -z "$HB_CONTENT" ]; then
    kind=nohb
    problem="$(msg "пульса нет — панель не запущена или не доходит до базы" "no heartbeat: the panel is not running or cannot reach the database")"
else
    ts=$(val ts); sealed=$(val sealed); ok=$(val alerts_ok)
    case "$ts" in ''|*[!0-9]*|0?*) ts=0 ;; esac
    [ "${#ts}" -le 12 ] || ts=0
    age=$(( NOW - ts ))
    if [ "$ts" -eq 0 ] || [ "$age" -gt "$MAX_AGE" ]; then
        kind=silent
        problem="$(msg "панель молчит ${age}с (порог ${MAX_AGE}с) — контейнер или база мертвы" "the panel has been silent for ${age}s (limit ${MAX_AGE}s): the container or the database is dead")"
    elif [ "$sealed" = "1" ]; then
        kind=sealed
        problem="$(msg "панель ЗАПЕРТА — значения не выдаются никому, включая серверы и кластеры" "the panel is SEALED: values are served to no one, servers and clusters included")"
    elif [ "$ok" = "0" ]; then
        kind=channel
        problem="$(msg "панель жива, но её канал оповещений сломан: последняя отправка не дошла или Telegram не отвечает" "the panel is alive but its alert channel is broken: the last delivery failed or Telegram does not answer")"
    fi
fi

panel=$(val panel); [ -z "$panel" ] && panel="$(hostname)"
tag="🚑 Sekvyr [$panel]"

# Состояние: первая строка - сообщали ли уже (ok|problem), вторая - счетчик,
# третья - вид проблемы на прошлой проверке, четвертая - вид, о котором
# сообщили. Без вида сторож, раз сообщив о проблеме, молчал до возврата в
# норму: панель, о которой сказали "заперта", могла потом умереть совсем, и
# об этом не узнавал никто.
STATE_CONTENT=$(read_host_state "$STATE") || STATE_CONTENT=''
state_line() { printf '%s\n' "$STATE_CONTENT" | sed -n "$1"p; }
alerted=$(state_line 1); [ -z "$alerted" ] && alerted=ok
strikes=$(state_line 2)
case "$strikes" in ''|*[!0-9]*|0?*) strikes=0 ;; esac
[ "${#strikes}" -le 9 ] || strikes=0
seen=$(state_line 3)
told=$(state_line 4)

if [ -n "$problem" ]; then
    # Состояние от прежней версии сторожа: о проблеме сообщили, а вид не
    # записан. Считаем, что сообщали о нынешней: иначе сразу после обновления
    # пришло бы второе сообщение о том же.
    if [ "$alerted" = "problem" ] && [ -z "$told" ]; then
        told="$kind"
        seen="$kind"
    fi
    # Новая беда после сообщения считается заново: о ней тоже сообщают, когда
    # она продержалась STRIKES проверок подряд, а не мелькнула на одной.
    if [ "$alerted" = "problem" ] && [ "$kind" != "$seen" ]; then
        strikes=1
    else
        strikes=$((strikes + 1))
    fi
    seen="$kind"
    if [ "$strikes" -ge "$STRIKES" ] && { [ "$alerted" != "problem" ] || [ "$kind" != "$told" ]; } &&
        send_host_alert "$HB_CONTENT" "$tag: $problem"; then
        alerted=problem
        told="$kind"
    fi
else
    strikes=0
    seen=""
    if [ "$alerted" = "problem" ] &&
        send_host_alert "$HB_CONTENT" "$(msg "✅ Sekvyr [$panel]: панель снова в норме" "✅ Sekvyr [$panel]: the panel is back to normal")"; then
        alerted=ok
        told=""
    fi
fi

mkdir -p "$(dirname "$STATE")" || exit 2
printf '%s\n%s\n%s\n%s\n' "$alerted" "$strikes" "$seen" "$told" | write_host_state "$STATE" 077
