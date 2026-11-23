# The panel owns its mounted data directory. Host jobs must treat its files as input.
read_host_state() {
    dd if="$1" iflag=nofollow,nonblock bs=8192 count=1 status=none 2>/dev/null
}

regular_or_absent() {
    [ ! -L "$1" ] && { [ ! -e "$1" ] || [ -f "$1" ]; }
}

write_host_state() (
    state="$1"
    umask "$2"
    # dd creates the staging file exclusively. Rename replaces the final entry
    # without opening it, even when the panel has made it a symlink.
    stage=$(mktemp -u -- "$state.XXXXXXXXXX") || exit 1
    trap 'rm -f -- "$stage"' EXIT
    dd of="$stage" conv=excl status=none && mv -fT -- "$stage" "$state"
)

heartbeat_field() {
    printf '%s\n' "$1" | sed -n "/^$2=/{s/^[^=]*=//;p;q;}"
}

curl_option() {
    value=$(printf '%s' "$2" | tr '\r\n' '  ' | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '%s = "%s"\n' "$1" "$value"
}

alert_url() {
    case "$1" in
        [Hh][Tt][Tt][Pp]://*|[Hh][Tt][Tt][Pp][Ss]://*) curl_option url "$1" ;;
        *) return 1 ;;
    esac
}

alert_post() {
    # Keep the URL and any credentials out of argv, and ignore the host curlrc.
    status=$(curl -q --silent --globoff --proto '=http,https' --max-time 15 \
        --output /dev/null --write-out '%{http_code}' --config -) || return 1
    case "$status" in 2[0-9][0-9]) return 0 ;; *) return 1 ;; esac
}

send_host_alert() (
    heartbeat="$1" message="$2"
    token=$(heartbeat_field "$heartbeat" tg_token)
    chat=$(heartbeat_field "$heartbeat" tg_chat)
    api=$(heartbeat_field "$heartbeat" tg_api)
    hook=$(heartbeat_field "$heartbeat" webhook)
    delivered=1
    if [ -n "$token" ] && [ -n "$chat" ]; then
        {
            alert_url "${api:-https://api.telegram.org}/bot$token/sendMessage" &&
            curl_option data-urlencode "chat_id=$chat" &&
            curl_option data-urlencode "text=$message" &&
            curl_option data-urlencode 'disable_web_page_preview=true'
        } | alert_post && delivered=0
    fi
    if [ -n "$hook" ]; then
        json=$(printf '%s' "$message" | tr '\r\n\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')
        {
            alert_url "$hook" &&
            curl_option header 'Content-Type: application/json' &&
            curl_option data "{\"text\": \"$json\"}"
        } | alert_post && delivered=0
    fi
    exit "$delivered"
)
