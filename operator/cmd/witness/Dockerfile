# Build with operator/ as the context.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN GOWORK=off go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOWORK=off \
    go build -trimpath -ldflags '-s -w -buildid=' -o /out/sekvyr-witness ./cmd/witness
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/sekvyr-witness /sekvyr-witness
USER 65532:65532
ENTRYPOINT ["/sekvyr-witness"]
LABEL org.opencontainers.image.title="Sekvyr witness development profile" \
      org.opencontainers.image.description="Explicit development filesystem journal; not WORM or production-ready" \
      org.opencontainers.image.source="https://github.com/mihsergeev/Sekvyr" \
      org.opencontainers.image.licenses="AGPL-3.0"
