# syntax=docker/dockerfile:1
ARG GOLANG_VERSION=1.26.4
ARG ALPINE_VERSION=3.23

# Stage 1: Build the gateway binary from source
# Use BUILDPLATFORM so Go cross-compiles natively (no QEMU for compiler)
FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG TARGETOS TARGETARCH

RUN apk --no-cache --virtual .build-deps add make gcc musl-dev binutils-gold git wget

COPY . /app
WORKDIR /app

# Per SCALE_STANDARD.md §2 — every Go production Dockerfile at the
# gateway edge or in any JSON-emitting subsystem builds with
# GOEXPERIMENT=jsonv2. Verified −12% time / −23% allocs on the edge
# POST roundtrip vs encoding/json v1 (json_bench_test.go in zip).
ARG GO_EXPERIMENT=jsonv2
ENV GOEXPERIMENT=${GO_EXPERIMENT}

# Private cross-repo modules (hanzoai/cloud, hanzoai/zip, luxfi/*) are fetched
# directly via authenticated git, bypassing the public proxy + checksum DB.
ENV GOPRIVATE=github.com/hanzoai/*,github.com/luxfi/*

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=gh_token \
    if [ -s /run/secrets/gh_token ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build && \
    CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build-ingress

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
  CMD wget -qO- http://localhost:8080/healthz || exit 1
