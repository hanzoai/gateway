# syntax=docker/dockerfile:1
ARG GOLANG_VERSION=1.26.5
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

# Modules resolve through the public proxy, which serves the immutable copy
# sum.golang.org signed. go.sum pins those hashes, so a re-cut tag cannot change
# what this image is built from.
#
# GONOSUMDB names the one namespace the public checksum database cannot cover:
# github.com/hanzoai/*, some of whose repos are private. Those fall through to a
# direct authenticated fetch (gh_token, below). Every other module — ours and
# third-party alike — is verified against sum.golang.org.
#
# GOFLAGS keeps its default (-mod=readonly), so the committed go.mod/go.sum are
# authoritative and drift fails the build instead of being rewritten in place.
ENV GONOSUMDB=github.com/hanzoai/* \
    GOPROXY=https://proxy.golang.org,direct

# GIT_AUTH_TOKEN, not gh_token. That is the secret id the fabric actually
# supplies: platform.hanzo.ai's runner emits
#
#     --secret id=GIT_AUTH_TOKEN,env=GIT_AUTH_TOKEN
#
# (cloud/apps/platform/k8s.go, buildFrontendCmd) with the value wired from the
# `console-git-token` Secret. It is also BuildKit's own gitsource credential, so
# ONE name covers both the git CONTEXT fetch and the module fetches below.
#
# `gh_token` was a name nothing on this lane supplied, and the failure was
# silent-by-design: `[ -s ]` on an absent mount is simply false, so no rewrite was
# installed, every private-module fetch went out anonymous, and the build died at
# the first one — github.com/hanzoai/log, which 404s to an unauthenticated
# client. The context clone had already succeeded from the same private org,
# which is what makes the shape confusing to read: the token was present in the
# job all along under the other name.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=GIT_AUTH_TOKEN \
    if [ -s /run/secrets/GIT_AUTH_TOKEN ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/GIT_AUTH_TOKEN)@github.com/".insteadOf "https://github.com/"; \
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
