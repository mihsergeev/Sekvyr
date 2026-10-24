FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Официальный nginx стартует мастер-процесс от root - только чтобы занять 80-й
# порт, который панели не нужен: наружу её публикует обратный прокси. Этот образ
# собран под работу от uid 101 и порт 8080.
FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html
EXPOSE 8080

# Без своих меток образ панели нес бы метки nginx-unprivileged: реестр и
# сканер показывали бы его источник, описание и версию 1.31 как наши. Удалить
# унаследованную метку нельзя, поэтому каждая из них задана заново.
ARG VERSION=dev
ARG REVISION=
LABEL maintainer="" \
      org.opencontainers.image.created="" \
      org.opencontainers.image.title="Sekvyr frontend" \
      org.opencontainers.image.description="Sekvyr web UI and the proxy in front of the panel API" \
      org.opencontainers.image.source="https://github.com/mihsergeev/Sekvyr" \
      org.opencontainers.image.url="https://sekvyr.ru" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0"
