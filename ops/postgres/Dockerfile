FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS gosu

# The upstream PostgreSQL image includes gosu 1.20 built with Go 1.24.6.
# Rebuild the same source with the patched standard library and Go checksum DB.
RUN CGO_ENABLED=0 GOTOOLCHAIN=local go install -trimpath github.com/tianon/gosu@29b939aa5bd4dc588af765b8248f6e39150d2565

FROM postgres:18.7-alpine@sha256:ff64c9e3bdf8e2120107d3559de8db314e8305f7e38c5105903c6295876738ff
# Apply stable fixes for the libraries bundled in the pinned base.
RUN apk upgrade --no-cache libxml2
COPY --from=gosu --chown=0:0 --chmod=0755 /go/bin/gosu /usr/local/bin/gosu
RUN gosu nobody true

ARG VERSION=dev
ARG REVISION=
LABEL org.opencontainers.image.title="Sekvyr postgres" \
      org.opencontainers.image.source="https://github.com/mihsergeev/Sekvyr" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
