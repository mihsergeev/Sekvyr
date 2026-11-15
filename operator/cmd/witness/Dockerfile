# Build with operator/ as the context.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
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
