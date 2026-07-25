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

# hanzoai/* and luxfi/* resolve via the IMMUTABLE public proxy — go.sum pins
# those canonical hashes, so a force-re-pointed tag can never break the build.
# Routing them DIRECT (the old GOPRIVATE approach) re-fetches a re-tagged tree
# (e.g. luxfi/zap@v0.8.8) whose hash differs from go.sum's proxy hash →
# "checksum mismatch / SECURITY ERROR". This matches the drop-GOPRIVATE fix
# already shipped in hanzoai/cloud + iam + luxfi/kms. Only zap-proto/* stays
# first-party-direct (kept in GOPRIVATE) — authenticated git via gh_token.
#
# GOSUMDB is NO LONGER `off`. A global `off` disabled checksum-database
# verification for the ENTIRE 1500-module graph, which fails OPEN: paired with
# GOFLAGS=-mod=mod it let any fetch rewrite go.sum from whatever the source
# served. The bypass is now scoped with GONOSUMDB to exactly the namespaces that
# genuinely cannot be in the public sumdb — our own first-party orgs, several of
# whose repos are private — while every third-party module is verified against
# sum.golang.org again.
#
# GOFLAGS no longer carries -mod=mod either: the default (-mod=readonly) makes
# the committed go.mod/go.sum authoritative and fails the build rather than
# silently rewriting them.
ENV GOPRIVATE=github.com/zap-proto/* \
    GONOSUMDB=github.com/zap-proto/*,github.com/hanzoai/*,github.com/luxfi/* \
    GOPROXY=https://proxy.golang.org,direct

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
