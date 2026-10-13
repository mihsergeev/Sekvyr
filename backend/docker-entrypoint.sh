#!/bin/sh
# Панель работает НЕ от root. Контейнер стартует от root только затем, чтобы
# выровнять владельца смонтированного тома, и сразу сбрасывает привилегии.
#
# Почему не просто USER в Dockerfile: каталог ./data на уже работающей установке
# мог быть создан прежним образом от root. С одним лишь USER контейнер поднялся
# бы и упал на первой же записи - уже после того, как обновление сочли удачным.
set -eu

DATA="${SEKVYR_DATA_DIR:-/data}"
APP_UID=10001

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA"
    # chown -R по каталогу с бэкапами не бесплатен, а нужен ровно один раз -
    # поэтому только когда владелец действительно не тот.
    if [ "$(stat -c %u "$DATA")" != "$APP_UID" ]; then
        # В stderr: stdout разовых команд (run backend ...) - это их данные.
        echo "entrypoint: подгоняю владельца $DATA под sekvyr ($APP_UID)" >&2
        # postgres - НЕ НАШ каталог: compose кладет кластер базы в ./data/postgres,
        # внутрь того же тома, и принадлежит он пользователю postgres. Забрать его
        # себе значит уронить базу - она не стартует с чужим владельцем PGDATA.
        find "$DATA" -mindepth 1 -maxdepth 1 -name postgres -prune -o \
             -exec chown -R "$APP_UID:$APP_UID" {} +
        chown "$APP_UID:$APP_UID" "$DATA"
    fi

    # Каталог для корневого ключа, если включено автоматическое отпирание.
    # Права 0700 ставим здесь: файл панель создает с 0600 сама, но каталог,
    # созданный докером от root, остался бы читаемым всем в контейнере.
    KEYFILE="${SEKVYR_ROOT_KEY_FILE:-}"
    if [ -n "$KEYFILE" ]; then
        KEYDIR=$(dirname "$KEYFILE")
        if [ "$KEYDIR" != "$DATA" ]; then
            mkdir -p "$KEYDIR"
            chown "$APP_UID:$APP_UID" "$KEYDIR"
            chmod 700 "$KEYDIR"
        fi
    fi

    exec gosu sekvyr "$@"
fi

# Уже не root (в compose задан user:) - просто запускаемся.
exec "$@"
