# Образ агента для Kubernetes: init-контейнер и спутник пода (deploy/kubernetes).
#
# Бинарь собирается так же, как тот, что раздает панель (backend/Dockerfile):
# тот же Go и те же флаги, поэтому хеш совпадает с подписанным manifest.json.
# Сборка идет на платформе сборщика, а GOARCH берется из целевой: без этого
# arm64 собирался бы в эмуляции, долго и тем же самым результатом.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -buildid= -X main.Version=$(cat VERSION) -X main.PublicKey=$(cat pubkey.txt)" \
    -o /out/sekvyr .

# alpine, а не scratch: --on-change выполняется через /bin/sh, а корневые
# сертификаты для TLS к панели в alpine уже есть.
FROM alpine:3.22
COPY --from=build /out/sekvyr /usr/local/bin/sekvyr
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/sekvyr"]
CMD ["help"]
