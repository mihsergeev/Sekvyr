# Агент собирается здесь же: панель раздает его нодам. Версия у него своя
# (agent/VERSION) - правка интерфейса панели не меняет бинарь и не требует новой
# подписи, а подпись здесь единственное, что отделяет обновление от "панель
# прислала что угодно и это выполнилось от root".
#
# -buildid= обязателен: build ID считается от содержимого исходников, и без
# него правка одного комментария давала другой бинарь, а с ним и 500 вместо
# агента, пока сборку не подпишут заново.
FROM golang:1.27.1-alpine AS agent
WORKDIR /src
COPY agent/ ./
RUN set -eu; \
    for arch in amd64 arm64; do \
        CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
        go build -trimpath -ldflags "-s -w -buildid= -X main.Version=$(cat VERSION) -X main.PublicKey=$(cat pubkey.txt)" \
            -o /out/sekvyr-linux-$arch .; \
    done

FROM python:3.12-slim

# Панель работает не от root. gosu нужен entrypoint'у: он стартует от root ровно
# затем, чтобы выровнять владельца смонтированного тома, и сразу сбрасывает
# привилегии. su/sudo для этого не годятся - они плодят промежуточный процесс и
# ломают доставку сигналов первому процессу контейнера.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends gosu; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd -r -g 10001 sekvyr; \
    useradd -r -u 10001 -g sekvyr -d /srv -s /usr/sbin/nologin sekvyr; \
    gosu nobody true      # проверяем на сборке, а не в три часа ночи на проде

WORKDIR /srv

COPY backend/pyproject.toml backend/constraints.txt ./
COPY backend/app ./app
# Версии - из constraints.txt: образ, собранный на сервере, совпадает с
# проверенным. pip после установки не нужен, а в образе он только добавляет
# находок сканерам и способов что-то доставить в работающий контейнер.
RUN pip install --no-cache-dir --root-user-action=ignore -c constraints.txt . && \
    pip uninstall -y --root-user-action=ignore pip

COPY backend/alembic.ini ./
COPY backend/alembic ./alembic

RUN chown -R sekvyr:sekvyr /srv

# Бинари агента и скрипт установки: их раздает машинный контур.
COPY --from=agent /out/ /srv/agent/
COPY agent/install.sh /srv/agent/install.sh
# Подписанное описание версии: по нему нода решает, ставить ли обновление.
COPY agent/manifest.json /srv/agent/manifest.json

COPY backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
