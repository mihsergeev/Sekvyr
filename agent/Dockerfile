# Образ агента для Kubernetes: init-контейнер и спутник пода (deploy/kubernetes).
#
# Бинарь собирается так же, как тот, что раздает панель (backend/Dockerfile):
# тот же Go и те же флаги, поэтому хеш совпадает с подписанным manifest.json.
# Сборка идет на платформе сборщика, а GOARCH берется из целевой: без этого
# arm64 собирался бы в эмуляции, долго и тем же самым результатом.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG TARGETARCH
WORKDIR /src
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -buildid= -X main.Version=$(cat VERSION) -X main.PublicKey=$(cat pubkey.txt)" \
    -o /out/sekvyr .

# alpine, а не scratch: --on-change выполняется через /bin/sh, а корневые
# сертификаты для TLS к панели в alpine уже есть.
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
COPY --from=build /out/sekvyr /usr/local/bin/sekvyr
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/sekvyr"]
CMD ["help"]

# Версия здесь - агента (agent/VERSION), ее передает release.yml.
ARG VERSION=dev
ARG REVISION=
LABEL org.opencontainers.image.title="Sekvyr agent" \
      org.opencontainers.image.description="Sekvyr agent for Kubernetes: an init container and a sidecar that write values from the panel" \
      org.opencontainers.image.source="https://github.com/mihsergeev/Sekvyr" \
      org.opencontainers.image.url="https://sekvyr.ru" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0"
