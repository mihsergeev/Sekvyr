# Агент собирается здесь же: панель раздает его нодам. Версия у него своя
# (agent/VERSION) - правка интерфейса панели не меняет бинарь и не требует новой
# подписи, а подпись здесь единственное, что отделяет обновление от "панель
# прислала что угодно и это выполнилось от root".
#
# -buildid= обязателен: build ID считается от содержимого исходников, и без
# него правка одного комментария давала другой бинарь, а с ним и 500 вместо
# агента, пока сборку не подпишут заново.
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS agent
WORKDIR /src
COPY agent/ ./
RUN set -eu; \
    for arch in amd64 arm64; do \
        CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
        go build -trimpath -ldflags "-s -w -buildid= -X main.Version=$(cat VERSION) -X main.PublicKey=$(cat pubkey.txt)" \
            -o /out/sekvyr-linux-$arch .; \
    done

FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

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

# В site-packages ставятся только зависимости, а не сам пакет: иначе код панели
# лежал бы в образе дважды, в /srv/app и в site-packages, и какая копия
# работает, зависело бы от каталога запуска. Версии - из constraints.txt: образ,
# собранный на сервере, совпадает с проверенным. pip после установки не нужен, а
# в образе он только добавляет находок сканерам и способов что-то доставить в
# работающий контейнер.
COPY backend/pyproject.toml backend/constraints.txt ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" > /tmp/requirements.txt && \
    pip install --no-cache-dir --root-user-action=ignore -c constraints.txt -r /tmp/requirements.txt && \
    pip uninstall -y --root-user-action=ignore pip && \
    rm -rf /tmp/requirements.txt /root/.cache

# Код принадлежит root: процесс панели (uid 10001) его только читает, а пишет в
# /data, /secret и /tmp. Захвативший процесс не перепишет код, который
# выполнится после перезапуска. Байт-код собирается здесь же: во время работы
# его некуда записать.
COPY backend/app ./app
COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
RUN python -m compileall -q app alembic
# Пакет app находится из любого каталога: alembic, uvicorn и разовые python -c
# из ops/*.sh.
ENV PYTHONPATH=/srv

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

# Метки в конце: смена версии не должна сбрасывать кэш слоев выше. Значения
# передает release.yml, у сборки из исходников версия dev.
ARG VERSION=dev
ARG REVISION=
LABEL org.opencontainers.image.title="Sekvyr backend" \
      org.opencontainers.image.description="Sekvyr panel API: secrets and environment values for servers and clusters" \
      org.opencontainers.image.source="https://github.com/mihsergeev/Sekvyr" \
      org.opencontainers.image.url="https://sekvyr.ru" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0"
