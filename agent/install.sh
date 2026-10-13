#!/bin/sh
# Подключение сервера к панели Sekvyr одной командой.
#
#   curl -fsSL https://ПАНЕЛЬ/api/v1/machine/install.sh | sudo sh -s -- --token ТОКЕН
#
# Что делает: кладет бинарь агента в /opt/sekvyr-agent, меняет одноразовый токен на
# постоянную машинную личность (секрет генерится панелью и остается на ноде с
# правами 0600) и заводит systemd-юнит, который держит файл окружения свежим.
#
# Несколько приложений на одной машине обслуживает ОДИН агент. Добавить
# приложение - одна короткая команда, перезапускать ничего не нужно:
#
#   sudo sekvyr add shop/prod
#
# Пути выводятся из имени проекта: файл /run/sekvyr/shop.env, а после изменения
# выполняется docker compose -f /app/shop/compose.yml up -d.
#
# Каталог агента задается флагом --dir. Нода, где агент уже стоит в прежнем
# каталоге /lib65/sekvyr, там и остается: переезд ради нового умолчания сломал
# бы ей юнит и самообновление.
#
# Снять агента с сервера (служба, бинарь, конфиг с секретом машины, ключ ноды,
# копия значений и файлы в /run/sekvyr):
#
#   curl -fsSL https://ПАНЕЛЬ/api/v1/machine/install.sh | sudo sh -s -- --uninstall
#
# Язык вывода: --lang ru или en (его добавляет панель: язык ее интерфейса),
# иначе SEKVYR_LANG, иначе русская локаль, иначе английский. Язык уходит и в
# конфиг агента: служба и `sekvyr add` говорят на нем же.
#
# Если наружу сервер ходит только через прокси, запустите установщик с
# HTTPS_PROXY (и NO_PROXY) в окружении: под sudo через sudo -E или
# export в root-шелле. Значения сохраняются для службы в
# /etc/sekvyr/proxy.env, поменять их потом - правкой этого файла и
# systemctl restart sekvyr-agent.
set -eu

# Все тело - одна функция, вызванная последней строкой. Под "curl | sh" скрипт
# приходит на stdin, и без этого оболочка выполняла бы его по мере чтения:
# дочерняя команда, читающая stdin (docker compose exec в бэкапе),
# съедала остаток скрипта, и он обрывался синтаксической ошибкой. Так же
# оборванная загрузка выполнилась бы наполовину. Функция читается целиком
# до первого действия.
main() {

PANEL="${SEKVYR_URL:-}"
TOKEN=""
PROJECT=""
ENVNAME=""
GROUP=""
# Пусто - агент берет приложения из списка в конфиге (sekvyr add). Флаг
# оставлен для нод, поставленных раньше: у них один файл, заданный явно.
OUT=""
UNIT="sekvyr-agent"
INTERVAL="60s"
ON_CHANGE=""
# Копия последних значений на диске (зашифрована ключом ноды) нужна, чтобы
# пересоздать контейнер, пока панель недоступна. Кому она не нужна - --no-cache.
NO_CACHE=""
UNINSTALL=""
# Подключить заново уже подключенный сервер: новая личность вместо прежней.
REENROLL=""
INTERVAL_SET=""
CACHE_SET=""
SKIP_ADD=""
SECOND_OUT=""
BIN_DIR=""
CONFIG="/etc/sekvyr/agent.json"
# Откуда брать личность для второго экземпляра: она уже есть, и заводить новую
# ради второго приложения на том же сервере незачем.
FROM_CONFIG="/etc/sekvyr/agent.json"

case "${SEKVYR_LANG:-}" in
    ru|en) OUT_LANG="$SEKVYR_LANG" ;;
    *) case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in ru*) OUT_LANG=ru ;; *) OUT_LANG=en ;; esac ;;
esac
# msg "по-русски" "in English"
msg() { if [ "$OUT_LANG" = ru ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }

while [ $# -gt 0 ]; do
    case "$1" in
        --url) PANEL="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --unit) UNIT="$2"; shift 2 ;;
        --config) CONFIG="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        --env) ENVNAME="$2"; shift 2 ;;
        --group) GROUP="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; INTERVAL_SET=1; shift 2 ;;
        --on-change) ON_CHANGE="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --dir) BIN_DIR="$2"; shift 2 ;;
        --no-cache) NO_CACHE=1; shift ;;
        # Вернуть копию значений, выключенную прошлой установкой.
        --cache) NO_CACHE=""; CACHE_SET=1; shift ;;
        --no-service) UNIT=""; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --reenroll) REENROLL=1; shift ;;
        --lang)
            case "$2" in ru|en) OUT_LANG="$2" ;; esac
            shift 2 ;;
        *) msg "неизвестный аргумент: $1" "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Снятие агента. Учетку машины в панели скрипт не трогает: машинный контур
# нарочно не умеет ничего удалять. Ее удаляют в панели, и до этого секрет
# машины, если его копия где-то осталась, продолжает действовать.
if [ -n "$UNINSTALL" ]; then
    if [ "$(id -u)" != "0" ]; then
        msg "нужен root: запустите через sudo" "root is required: run it with sudo" >&2
        exit 2
    fi
    [ -n "$UNIT" ] || UNIT=sekvyr-agent
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$UNIT.service"
        rm -rf "/etc/systemd/system/$UNIT.service.d"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    # Удаляем только свои файлы, а каталог - если он после этого пуст: --dir
    # мог указать на общий каталог (/usr/local/bin, /opt), и rm -rf стер бы в
    # нем все чужое.
    for dir in "${BIN_DIR:-/opt/sekvyr-agent}" /opt/sekvyr-agent /lib65/sekvyr; do
        if [ -f "$dir/sekvyr" ]; then
            rm -f "$dir/sekvyr" "$dir/sekvyr.new"
            rmdir "$dir" 2>/dev/null || true
        fi
    done
    rm -f /usr/local/bin/sekvyr
    [ -L /usr/bin/sekvyr ] && rm -f /usr/bin/sekvyr
    # Секрет машины, ключ ноды, шифрованная копия значений и файлы с самими
    # значениями: после снятия на сервере не должно остаться ничего, что
    # открывает доступ к панели или к ее значениям.
    rm -f "$CONFIG" "$(dirname "$CONFIG")/proxy.env"
    rm -rf /etc/sekvyr /var/lib/sekvyr /run/sekvyr
    msg "sekvyr: агент снят. Удалите сервер и в панели (Серверы, меню сервера): до этого его учетка действует." \
        "sekvyr: the agent is removed. Delete the server in the panel too (Servers, the server menu): until then its identity stays valid."
    exit 0
fi

# Токен нужен только при первом подключении. Повторный запуск обновляет
# бинарь и оставляет прежнюю личность: тратить одноразовый токен на каждое
# обновление незачем, да и агент с 0.18.0 обновляется сам.
if [ -z "$PANEL" ]; then
    msg "нужен --url" "--url is required" >&2
    exit 2
fi
# Команда старого режима с одним файлом уходит в ExecStart юнита в одинарных
# кавычках, и кавычку внутри нее там не записать, как и перенос строки.
# Проверяем до установки, чтобы не оставить ноду наполовину подключенной.
if [ -n "$OUT" ] && [ -n "$UNIT" ]; then
    case "$ON_CHANGE" in
        *"'"*|*"
"*)
            msg "кавычка ' или перенос строки в --on-change ломают юнит: задайте команду через sekvyr add --on-change" \
                "a ' quote or a line break in --on-change breaks the unit: set the command with sekvyr add --on-change" >&2
            exit 2 ;;
    esac
fi
# Пути уходят в юнит как есть: systemd делит ExecStart по пробелам, а %, $ и
# обратный слеш раскрывает сам. Такой путь проще не принять, чем экранировать.
unit_path() {
    case "$2" in
        *" "*|*"'"*|*'"'*|*'\'*|*%*|*'$'*)
            msg "в пути $1 не должно быть пробела, кавычек, \\, % и \$: systemd прочтет его иначе" \
                "the $1 path must not contain a space, quotes, \\, % or \$: systemd would read it differently" >&2
            exit 2 ;;
    esac
}
if [ -n "$UNIT" ]; then
    unit_path --out "$OUT"
    unit_path --config "$CONFIG"
    unit_path --dir "$BIN_DIR"
fi
if [ -z "$TOKEN" ] && [ ! -f "$CONFIG" ] && [ ! -f "$FROM_CONFIG" ]; then
    msg "нужен --token: сервер ещё не подключён" "--token is required: this server is not connected yet" >&2
    exit 2
fi
if [ "$(id -u)" != "0" ]; then
    msg "нужен root: запустите через sudo" "root is required: run it with sudo" >&2
    exit 2
fi
# Без systemd служба не встанет, а узнавать это после подключения поздно:
# одноразовый токен уже потрачен, и установщик падал на записи юнита с
# невнятной ошибкой. Проверяем до всего.
if [ -n "$UNIT" ] && { ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; }; then
    msg "на сервере нет работающего systemd: поставьте агента с --no-service и запускайте его сами (sekvyr agent --config $CONFIG) - из OpenRC, supervisord или контейнера" \
        "this server has no running systemd: install the agent with --no-service and run it yourself (sekvyr agent --config $CONFIG) from OpenRC, supervisord or a container" >&2
    exit 2
fi

if [ -z "$BIN_DIR" ]; then
    BIN_DIR="/opt/sekvyr-agent"
    if [ ! -x "$BIN_DIR/sekvyr" ] && [ -x /lib65/sekvyr/sekvyr ]; then
        BIN_DIR="/lib65/sekvyr"
    fi
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) msg "неподдерживаемая архитектура: $ARCH" "unsupported architecture: $ARCH" >&2; exit 2 ;;
esac

msg "sekvyr: качаю агента ($ARCH)" "sekvyr: downloading the agent ($ARCH)"
mkdir -p "$BIN_DIR"
TMP="$BIN_DIR/sekvyr.new"
curl -fsSL "$PANEL/api/v1/machine/agent?arch=$ARCH" -o "$TMP"

# Сверяем с подписанным описанием. Первую установку все равно приходится
# доверить панели и её TLS - подписи здесь проверять нечем, ключа на чистой ноде
# еще нет. Зато дальше обновляется сам агент, и вот там подпись проверяется
# по ключу, вшитому в бинарь: панель уже не сможет подсунуть что угодно.
WANT="$(curl -fsSL "$PANEL/api/v1/machine/agent/manifest" | grep -o "\"$ARCH\"[^}]*" | grep -oE '[0-9a-f]{64}' | head -1)"
# Хеша для этой архитектуры в описании нет - бинарь не с чем сверить, и
# молча ставить его нельзя (описание подписывали только для одной
# архитектуры, или панель отдала не то).
if [ -z "$WANT" ]; then
    rm -f "$TMP"
    msg "sekvyr: в описании версии нет хеша для $ARCH - установка отменена" \
        "sekvyr: the release description has no hash for $ARCH, installation cancelled" >&2
    exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    msg "sekvyr: нет sha256sum, хеш агента не сверен" "sekvyr: no sha256sum, the agent hash was not checked" >&2
fi
if command -v sha256sum >/dev/null 2>&1; then
    GOT="$(sha256sum "$TMP" | cut -d' ' -f1)"
    if [ "$GOT" != "$WANT" ]; then
        rm -f "$TMP"
        msg "sekvyr: хеш скачанного агента не совпал с описанием — установка отменена" \
            "sekvyr: the downloaded agent does not match the release hash, installation cancelled" >&2
        exit 1
    fi
    msg "sekvyr: хеш сошёлся с описанием" "sekvyr: the hash matches the release"
fi

chmod 0755 "$TMP"
mv "$TMP" "$BIN_DIR/sekvyr"
ln -sf "$BIN_DIR/sekvyr" /usr/local/bin/sekvyr 2>/dev/null || true
# На RHEL, Rocky и Alma secure_path sudo не содержит /usr/local/bin, и
# "sudo sekvyr add" из панели давал "command not found". Чужой /usr/bin/sekvyr
# не трогаем.
if [ ! -e /usr/bin/sekvyr ] || [ -L /usr/bin/sekvyr ]; then
    ln -sf "$BIN_DIR/sekvyr" /usr/bin/sekvyr 2>/dev/null || true
fi

# Язык дальше задает агенту не окружение, а этот выбор: так вывод агента
# совпадает с выводом установщика.
SEKVYR_LANG="$OUT_LANG"
export SEKVYR_LANG

if [ -n "$TOKEN" ] && [ -f "$CONFIG" ] && [ -z "$REENROLL" ]; then
    # Команду "новый сервер" берут из панели и для подключенного. Новая
    # личность оставила бы старую в панели с правами, а приложения из
    # sekvyr add пропали бы из списка, и их файлы молча перестали бы
    # обновляться. Токен остается неиспользованным.
    msg "sekvyr: сервер уже подключен ($CONFIG), токен не использован, обновлен только бинарь." \
        "sekvyr: this server is already connected ($CONFIG), the token was not used, only the binary was updated."
    msg "  Окружение ему выдается в панели на странице сервера (\"Подключить приложение\"). Подключить заново с новой личностью: --reenroll" \
        "  Grant it an environment in the panel on the server page (\"Connect an application\"). To connect again with a new identity: --reenroll"
    # Окружение из этой команды выдано другой, новой машине, а не этой: add
    # дал бы 403 каждую минуту.
    SKIP_ADD=1
elif [ -n "$REENROLL" ] && [ -z "$TOKEN" ]; then
    msg "для --reenroll нужен --token: возьмите команду \"Подключить сервер\" в панели" \
        "--reenroll needs --token: take the \"Connect a server\" command from the panel" >&2
    exit 2
elif [ -n "$TOKEN" ]; then
    msg "sekvyr: подключаю сервер к панели" "sekvyr: connecting this server to the panel"
    "$BIN_DIR/sekvyr" enroll --url "$PANEL" --token "$TOKEN" --config "$CONFIG" \
        ${NAME:+--name "$NAME"} --lang "$OUT_LANG" ${REENROLL:+--force}
elif [ ! -f "$CONFIG" ] && [ -f "$FROM_CONFIG" ]; then
    # Второй экземпляр на том же сервере: личность одна, окружение другое.
    # Секрет не перевыпускаем - иначе первый агент останется без доступа.
    msg "sekvyr: беру личность из $FROM_CONFIG для нового конфига $CONFIG" \
        "sekvyr: taking the identity from $FROM_CONFIG for the new config $CONFIG"
    if [ -z "$PROJECT" ] || [ -z "$ENVNAME" ]; then
        msg "нужны --project и --env: какое окружение должен тянуть этот агент" \
            "--project and --env are required: which environment this agent should pull" >&2
        exit 2
    fi
    "$BIN_DIR/sekvyr" config --from "$FROM_CONFIG" -o "$CONFIG" \
        --project "$PROJECT" --env "$ENVNAME" ${GROUP:+--group "$GROUP"}
    # Файл по умолчанию тот же /run/sekvyr/ПРОЕКТ.env, что у основного агента
    # для другого окружения того же проекта: два агента переписывали бы его по
    # очереди, и прод получал значения stage.
    if [ -z "$OUT" ] && "$BIN_DIR/sekvyr" ls --paths --config "$FROM_CONFIG" 2>/dev/null \
        | grep -qx "/run/sekvyr/$PROJECT.env"; then
        SECOND_OUT="/run/sekvyr/$PROJECT-$ENVNAME.env"
        msg "sekvyr: файл /run/sekvyr/$PROJECT.env уже пишет основной агент, этот будет писать $SECOND_OUT" \
            "sekvyr: /run/sekvyr/$PROJECT.env is already written by the main agent, this one writes $SECOND_OUT"
    fi
else
    msg "sekvyr: сервер уже подключён, обновлён только бинарь" \
        "sekvyr: this server is already connected, only the binary was updated"
fi

if [ -n "$PROJECT" ] && [ -n "$ENVNAME" ] && [ -z "$OUT" ] && [ -z "$SKIP_ADD" ]; then
    # Строку о результате печатает сам add: после enroll приложение уже в
    # списке, и "добавляю" перед "уже подключено" читалось бы как противоречие.
    "$BIN_DIR/sekvyr" add --config "$CONFIG" \
        ${ON_CHANGE:+--on-change "$ON_CHANGE"} \
        ${SECOND_OUT:+-o "$SECOND_OUT"} \
        "${GROUP:+$GROUP/}$PROJECT/$ENVNAME"
fi

if [ -n "$UNIT" ]; then
    msg "sekvyr: ставлю systemd-юнит $UNIT" "sekvyr: installing the systemd unit $UNIT"
    # Юнит переписывается при каждом запуске. То, что задали при установке
    # (--no-cache, --interval), без флагов в этот раз не должно молча
    # пропадать: копия значений на диске включилась бы обратно.
    OLD_UNIT="/etc/systemd/system/$UNIT.service"
    if [ -f "$OLD_UNIT" ]; then
        # Только среди флагов агента: текст --on-change ("docker compose build
        # --no-cache") идет после --out и к копии значений отношения не имеет.
        OLD_FLAGS="$(grep -m1 '^ExecStart=' "$OLD_UNIT" | sed -e 's/ --out .*//' -e 's/ --on-change .*//')"
        if [ -z "$NO_CACHE" ] && [ -z "$CACHE_SET" ] && printf '%s\n' "$OLD_FLAGS" | grep -q -- ' --no-cache'; then
            NO_CACHE=1
            msg "sekvyr: --no-cache сохранен с прошлой установки (вернуть копию значений: --cache)" \
                "sekvyr: --no-cache kept from the previous installation (to turn the copy of values back on: --cache)"
        fi
        if [ -z "$INTERVAL_SET" ]; then
            OLD_INTERVAL="$(grep -o -- '--interval [^ ]*' "$OLD_UNIT" | head -n 1 | cut -d' ' -f2)"
            [ -n "$OLD_INTERVAL" ] && INTERVAL="$OLD_INTERVAL"
        fi
    fi
    # Второй экземпляр: перезапуск после самообновления - свой, а общий
    # /run/sekvyr при его остановке не удаляется у основного агента.
    UNIT_RESTART=""
    UNIT_PRESERVE="restart"
    if [ "$UNIT" != "sekvyr-agent" ]; then
        UNIT_RESTART=" --restart-unit $UNIT"
        UNIT_PRESERVE="yes"
    fi
    # Флаги -o и --on-change у службы нужны только старому режиму с одним
    # файлом: в режиме списка команда живет в конфиге (sekvyr add). systemd сам
    # раскрывает в ExecStart $, % и обратный слеш (\n для него перенос строки
    # даже в кавычках), поэтому в команде они удваиваются, а одинарную кавычку
    # внутри одинарных кавычек юнита не записать вовсе.
    UNIT_APP=""
    if [ -n "$OUT" ]; then
        UNIT_APP=" -o $OUT"
        if [ -n "$ON_CHANGE" ]; then
            UNIT_APP="$UNIT_APP --on-change '$(printf '%s' "$ON_CHANGE" | sed -e 's/\\/\\\\/g' -e 's/%/%%/g' -e 's/[$]/$$/g')'"
        fi
    fi
    # Каталоги файлов приложений: юнит переписывается при каждом запуске
    # установщика, и каталог файла, заданного раньше через --out или
    # sekvyr add -o, иначе пропадал из ReadWritePaths - служба переставала
    # его писать. Путь, который systemd прочел бы иначе, пропускаем с
    # предупреждением.
    APP_DIRS=""
    APP_FILES="$("$BIN_DIR/sekvyr" ls --paths --config "$CONFIG" 2>/dev/null || true)"
    if [ -n "$OUT" ]; then
        APP_FILES="$APP_FILES
$OUT"
    fi
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        dir="$(dirname "$file")"
        case "$dir" in
            /run/sekvyr|/run/sekvyr/*) continue ;;
            /*) ;;
            *) continue ;;
        esac
        case "$dir" in
            *" "*|*"'"*|*'"'*|*'\'*|*%*|*'$'*)
                msg "sekvyr: каталог $dir не добавлен в ReadWritePaths: systemd прочтет его иначе" \
                    "sekvyr: $dir was not added to ReadWritePaths: systemd would read it differently" >&2
                continue ;;
        esac
        # С минусом: каталога может не быть при старте (каталог в /run после
        # перезагрузки), и без минуса systemd не поднял бы службу целиком.
        case " $APP_DIRS " in *" -$dir "*) ;; *) APP_DIRS="$APP_DIRS -$dir" ;; esac
    done <<APPFILES
$APP_FILES
APPFILES
    if [ "$OUT_LANG" = ru ]; then
        C_TMPFS="# Файл с секретами живет в tmpfs: переживает перезапуск агента, в том числе обновление, но не остановку службы и не перезагрузку."
        C_STATE="# Ключ ноды и копия значений: /etc здесь только на чтение, состояние в /var/lib/sekvyr."
        C_RW="# Писать агент может только в свои каталоги: файл со значениями, себя (обновление) и конфиг. Команда после изменения работает в тех же рамках."
        C_HOME="# Домашние каталоги только на чтение: команде после изменения нужны плагин docker compose и вход в реестр из /root/.docker."
    else
        C_TMPFS="# The secrets file lives in tmpfs: it survives agent restarts, updates included, but not a stop of the service or a reboot."
        C_STATE="# The node key and the copy of values: /etc is read-only here, state lives in /var/lib/sekvyr."
        C_RW="# The agent writes only to its own directories: the values file, itself (updates) and its config. The command after a change runs within the same limits."
        C_HOME="# Home directories are read-only: the command after a change needs the docker compose plugin and the registry login from /root/.docker."
    fi
    # Прокси - из окружения установщика в файл для службы: systemd окружение
    # шелла не наследует, и служба с прокси в профиле root каждую минуту
    # упиралась в таймаут, хотя установка прошла. Файл 0600: в адресе прокси
    # бывает пароль. Без прокси в окружении прежний файл не трогается.
    PROXY_ENV="$(dirname "$CONFIG")/proxy.env"
    PROXY_LINES=""
    for var in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy; do
        eval "val=\${$var:-}"
        # В одинарных кавычках systemd берет значение как есть (обратный слеш
        # и кавычку в начале без них он съел бы). Значение с апострофом или
        # переносом строки так не записать - оно пропускается.
        case "$val" in
            "") ;;
            *"
"*|*"'"*)
                msg "sekvyr: $var не сохранен для службы: в нем апостроф или перенос строки" \
                    "sekvyr: $var was not saved for the service: it has a quote or a line break" >&2 ;;
            *) PROXY_LINES="$PROXY_LINES$var='$val'
" ;;
        esac
    done
    if [ -n "$PROXY_LINES" ]; then
        mkdir -p "$(dirname "$PROXY_ENV")"
        # Заново, а не поверх: у прежнего файла могли быть права шире 0600.
        rm -f "$PROXY_ENV"
        (umask 077 && printf '%s' "$PROXY_LINES" > "$PROXY_ENV")
        msg "sekvyr: прокси для службы сохранен в $PROXY_ENV" "sekvyr: the proxy for the service is saved to $PROXY_ENV"
    fi
    cat > "/etc/systemd/system/$UNIT.service" <<UNITFILE
[Unit]
Description=Sekvyr agent ($UNIT)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/sekvyr agent --config $CONFIG --interval $INTERVAL${NO_CACHE:+ --no-cache}$UNIT_RESTART$UNIT_APP
Environment=SEKVYR_LANG=$OUT_LANG
EnvironmentFile=-$PROXY_ENV
Restart=always
RestartSec=10
$C_TMPFS
RuntimeDirectory=sekvyr
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=$UNIT_PRESERVE
$C_STATE
StateDirectory=sekvyr
StateDirectoryMode=0700
NoNewPrivileges=true
ProtectSystem=strict
$C_HOME
ProtectHome=read-only
PrivateTmp=true
$C_RW
ReadWritePaths=/run/sekvyr $BIN_DIR $(dirname "$CONFIG")$APP_DIRS

[Install]
WantedBy=multi-user.target
UNITFILE
    systemctl daemon-reload
    systemctl enable "$UNIT"
    systemctl restart "$UNIT"
    msg "sekvyr: юнит запущен — systemctl status $UNIT" "sekvyr: the unit is running: systemctl status $UNIT"
fi

if [ -z "$UNIT" ]; then
    msg "sekvyr: служба не ставилась (--no-service): запускайте агента сами - $BIN_DIR/sekvyr agent --config $CONFIG${OUT:+ -o $OUT}" \
        "sekvyr: no service was installed (--no-service): run the agent yourself - $BIN_DIR/sekvyr agent --config $CONFIG${OUT:+ -o $OUT}"
fi
msg "sekvyr: готово" "sekvyr: done"
}

main "$@"
