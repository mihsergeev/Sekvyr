#!/bin/sh
# Поведение agent/install.sh без root, systemd и сети: id, curl, ln и сам
# агент подменены заглушками, а заглушки пишут в журнал, кого и как вызвали.
#
#   sh agent/install_test.sh
#
# Главное, что здесь проверяется: на уже подключенной ноде бинарь меняет
# стоящий агент (sekvyr update, по подписи выпуска), а не скачанное с панели.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STUBS="$WORK/stubs"
LOG="$WORK/log"
mkdir -p "$STUBS"

# Агент-заглушка: пишет в журнал свои аргументы. update завершается с кодом из
# FAKE_UPDATE_RC; ls и прочее молча проходят.
fake_agent() {
    cat > "$1" <<EOF
#!/bin/sh
echo "$2 \$*" >> "$LOG"
if [ "\${1:-}" = update ]; then exit "\${FAKE_UPDATE_RC:-0}"; fi
exit 0
EOF
    chmod 0755 "$1"
}

fake_agent "$WORK/new-agent" "new-agent"

cat > "$STUBS/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then echo 0; exit 0; fi
exec /usr/bin/id "$@"
EOF
cat > "$STUBS/ln" <<EOF
#!/bin/sh
echo "ln \$*" >> "$LOG"
EOF
# curl отдает описание с хешем new-agent и сам new-agent вместо бинаря.
cat > "$STUBS/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$LOG"
out=""
url=""
while [ \$# -gt 0 ]; do
    case "\$1" in
        -o) out="\$2"; shift 2 ;;
        http*) url="\$1"; shift ;;
        *) shift ;;
    esac
done
case "\$url" in
    */agent/manifest)
        sum=\$(sha256sum "$WORK/new-agent" | cut -d' ' -f1)
        printf '{"version":"9.9.9","files":{"amd64":{"sha256":"%s"},"arm64":{"sha256":"%s"}}}' "\$sum" "\$sum" ;;
    *) cp "$WORK/new-agent" "\$out" ;;
esac
EOF
chmod 0755 "$STUBS/id" "$STUBS/ln" "$STUBS/curl"

FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }

# run <имя> <ожидаемый код> [аргументы install.sh]
run() {
    name="$1"; want="$2"; shift 2
    : > "$LOG"
    rc=0
    SEKVYR_LANG=en PATH="$STUBS:$PATH" sh "$HERE/install.sh" \
        --url https://panel.example --dir "$WORK/bin" --config "$WORK/etc/agent.json" \
        --no-service "$@" > "$WORK/out" 2>&1 || rc=$?
    if [ "$rc" != "$want" ]; then
        fail "$name: exit $rc, expected $want"
        sed 's/^/    /' "$WORK/out"
    fi
}

reset_node() {
    rm -rf "$WORK/bin" "$WORK/etc"
    mkdir -p "$WORK/bin" "$WORK/etc"
}

# 1. Подключенная нода: обновляет стоящий агент, с панели ничего не качается.
reset_node
echo '{"url":"https://panel.example"}' > "$WORK/etc/agent.json"
fake_agent "$WORK/bin/sekvyr" "old-agent"
run "connected" 0
grep -q "^old-agent update --config $WORK/etc/agent.json\$" "$LOG" || fail "connected: no sekvyr update by the installed agent"
grep -q "^curl " "$LOG" && fail "connected: the binary was downloaded from the panel"
grep -q "echo \"old-agent " "$WORK/bin/sekvyr" || fail "connected: the installed binary was replaced"

# 2. Стоящий агент отклонил версию (подпись, откат): установка останавливается.
reset_node
echo '{"url":"https://panel.example"}' > "$WORK/etc/agent.json"
fake_agent "$WORK/bin/sekvyr" "old-agent"
export FAKE_UPDATE_RC=1
run "rejected" 1
unset FAKE_UPDATE_RC
grep -q "^curl " "$LOG" && fail "rejected: fell back to downloading from the panel"
grep -q "echo \"old-agent " "$WORK/bin/sekvyr" || fail "rejected: the installed binary was replaced"

# 3. Подключенная нода с токеном (команда "новый сервер"): тоже через агента.
reset_node
echo '{"url":"https://panel.example"}' > "$WORK/etc/agent.json"
fake_agent "$WORK/bin/sekvyr" "old-agent"
run "connected with a token" 0 --token tok
grep -q "^curl " "$LOG" && fail "connected with a token: the binary was downloaded from the panel"
grep -q "enroll" "$LOG" && fail "connected with a token: the token was used"

# 4. --reenroll: нода может переезжать на другую панель, бинарь с панели.
reset_node
echo '{"url":"https://old-panel.example"}' > "$WORK/etc/agent.json"
fake_agent "$WORK/bin/sekvyr" "old-agent"
run "reenroll" 0 --token tok --reenroll
grep -q "^curl .*agent?arch=" "$LOG" || fail "reenroll: the binary was not downloaded"
grep -q "^new-agent enroll .*--force" "$LOG" || fail "reenroll: no enroll by the new binary"

# 5. Чистая нода: бинарь с панели, сверка хеша с описанием, подключение.
reset_node
run "fresh" 0 --token tok
grep -q "^curl .*agent?arch=" "$LOG" || fail "fresh: the binary was not downloaded"
grep -q "^new-agent enroll --url https://panel.example --token tok" "$LOG" || fail "fresh: no enroll"
grep -q "echo \"new-agent " "$WORK/bin/sekvyr" || fail "fresh: the binary was not installed"

# 6. Чистая нода без токена: отказ до всякого скачивания.
reset_node
run "fresh without a token" 2
grep -q "^curl " "$LOG" && fail "fresh without a token: something was downloaded"

# 7. Повторный запуск с --lang на подключенной ноде: язык уходит и в конфиг,
# иначе sudo sekvyr add говорил бы на прежнем.
reset_node
echo '{"url":"https://panel.example"}' > "$WORK/etc/agent.json"
fake_agent "$WORK/bin/sekvyr" "old-agent"
run "connected with --lang" 0 --lang ru
grep -q "^old-agent lang --config $WORK/etc/agent.json ru\$" "$LOG" || fail "connected with --lang: the language was not written to the config"

# 8. Без --lang язык конфига не трогается: его мог задать человек.
reset_node
echo '{"url":"https://panel.example"}' > "$WORK/etc/agent.json"
fake_agent "$WORK/bin/sekvyr" "old-agent"
run "connected without --lang" 0
grep -q "^old-agent lang" "$LOG" && fail "connected without --lang: the config language was changed"

if [ "$FAILED" = 0 ]; then
    echo "install.sh: all cases passed"
fi
exit "$FAILED"
