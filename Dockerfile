# syntax=docker/dockerfile:1
ARG GOLANG_VERSION=1.26.1
ARG ALPINE_VERSION=3.23

# Stage 1: Build the gateway binary from source
# Use BUILDPLATFORM so Go cross-compiles natively (no QEMU for compiler)
FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG TARGETOS TARGETARCH

RUN apk --no-cache --virtual .build-deps add make gcc musl-dev binutils-gold git wget

COPY . /app
WORKDIR /app

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build-ingress

# Stage 2: Runtime image
FROM alpine:${ALPINE_VERSION}

LABEL maintainer="dev@hanzo.ai"

RUN apk upgrade --no-cache --no-interactive && \
    apk add --no-cache ca-certificates tzdata && \
    adduser -u 1000 -S -D -H gateway && \
    mkdir /etc/gateway /etc/ingress && \
    echo '{ "version": 3 }' > /etc/gateway/gateway.json

COPY --from=builder /app/gateway /usr/bin/gateway
COPY --from=builder /app/ingress /usr/bin/ingress

# Bake in configs for the target cluster
ARG CONFIG=hanzo
COPY configs/${CONFIG}/gateway.json /etc/gateway/gateway.json
COPY configs/${CONFIG}/ingress.json /etc/ingress/ingress.json

USER 1000

WORKDIR /etc/gateway

ENTRYPOINT [ "/usr/bin/gateway" ]
CMD [ "run", "-c", "/etc/gateway/gateway.json" ]

EXPOSE 8080 8090

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/__health || exit 1
