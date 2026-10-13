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

pick_lang

HB="${SEKVYR_HEARTBEAT:-$APP/data/heartbeat}"
STATE="${SEKVYR_WATCHDOG_STATE:-$APP/data/watchdog.state}"
MAX_AGE="${SEKVYR_HB_MAX_AGE:-600}"
# Проверок подряд с проблемой до тревоги: перезапуск при обновлении не должен
# будить людей, а настоящая поломка живет дольше двух проверок.
STRIKES="${SEKVYR_WD_STRIKES:-2}"
NOW=$(date +%s)

val() { grep -m1 "^$1=" "$HB" 2>/dev/null | cut -d= -f2-; }

send() {
    _msg="$1" _token="$(val tg_token)" _chat="$(val tg_chat)"
    _api="$(val tg_api)"; [ -z "$_api" ] && _api="https://api.telegram.org"
    _hook="$(val webhook)"
    if [ -n "$_token" ] && [ -n "$_chat" ]; then
        curl -s --max-time 15 "$_api/bot$_token/sendMessage" \
            --data-urlencode "chat_id=$_chat" --data-urlencode "text=$_msg" \
            --data-urlencode "disable_web_page_preview=true" >/dev/null 2>&1
    fi
    if [ -n "$_hook" ]; then
        curl -s --max-time 15 -H 'Content-Type: application/json' \
            --data "{\"text\": \"$(printf '%s' "$_msg" | sed 's/\\/\\\\/g; s/"/\\"/g')\"}" \
            "$_hook" >/dev/null 2>&1
    fi
}

problem=""
if [ ! -f "$HB" ]; then
    problem="$(msg "пульса нет — панель не запущена или не доходит до базы" "no heartbeat: the panel is not running or cannot reach the database")"
else
    ts=$(val ts); sealed=$(val sealed); ok=$(val alerts_ok)
    age=$(( NOW - ${ts:-0} ))
    if [ "${ts:-0}" -eq 0 ] || [ "$age" -gt "$MAX_AGE" ]; then
        problem="$(msg "панель молчит ${age}с (порог ${MAX_AGE}с) — контейнер или база мертвы" "the panel has been silent for ${age}s (limit ${MAX_AGE}s): the container or the database is dead")"
    elif [ "$sealed" = "1" ]; then
        problem="$(msg "панель ЗАПЕРТА — значения не выдаются никому, включая серверы и кластеры" "the panel is SEALED: values are served to no one, servers and clusters included")"
    elif [ "$ok" = "0" ]; then
        problem="$(msg "панель жива, но её канал оповещений сломан: последняя отправка не дошла или Telegram не отвечает" "the panel is alive but its alert channel is broken: the last delivery failed or Telegram does not answer")"
    fi
fi

panel=$(val panel); [ -z "$panel" ] && panel="$(hostname)"
tag="🚑 Sekvyr [$panel]"

# Состояние: первая строка - сообщали ли уже (ok|problem), вторая - счетчик.
alerted=$(sed -n 1p "$STATE" 2>/dev/null); [ -z "$alerted" ] && alerted=ok
strikes=$(sed -n 2p "$STATE" 2>/dev/null)
case "$strikes" in ''|*[!0-9]*) strikes=0 ;; esac

if [ -n "$problem" ]; then
    strikes=$((strikes + 1))
    if [ "$alerted" != "problem" ] && [ "$strikes" -ge "$STRIKES" ]; then
        send "$tag: $problem"
        alerted=problem
    fi
else
    strikes=0
    if [ "$alerted" = "problem" ]; then
        send "$(msg "✅ Sekvyr [$panel]: панель снова в норме" "✅ Sekvyr [$panel]: the panel is back to normal")"
        alerted=ok
    fi
fi

mkdir -p "$(dirname "$STATE")"
printf '%s\n%s\n' "$alerted" "$strikes" > "$STATE"
