# Build from the operator directory, with the reviewed project compiler pin.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN GOWORK=off go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOWORK=off \
    go build -trimpath -ldflags '-s -w -buildid=' -o /out/sekvyr-operator ./cmd/operator
RUN for command in fencer witness journal-gateway checkpoint-recovery; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOWORK=off \
      go build -trimpath -ldflags '-s -w -buildid=' -o /out/sekvyr-$command ./cmd/$command || exit 1; \
    done

# Offline provisioning is distributed separately; it has no online authority.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOWORK=off \
    go build -trimpath -ldflags '-s -w -buildid=' -o /out-provision/sekvyr-provision ./cmd/provision

FROM scratch AS provision-artifacts
COPY --from=build /out-provision/ /

# No shell or package manager. System CAs come from the pinned build image.
FROM scratch AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /
USER 65532:65532
ENTRYPOINT ["/sekvyr-operator"]
ARG VERSION=0.1.0-rc.4
ARG REVISION=
LABEL org.opencontainers.image.title="Sekvyr operator" \
      org.opencontainers.image.description="Explicit Plain and E2E2 synchronization, canonical journal and opt-in HA fencing trial" \
      org.opencontainers.image.source="https://github.com/mihsergeev/Sekvyr" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0"
