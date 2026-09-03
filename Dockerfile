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

# The account files the scratch stage copies. Written here because scratch has no
# adduser, and named .gateway so they cannot be confused with the builder's own.
RUN printf 'gateway:x:1000:1000::/etc/gateway:/sbin/nologin\n' > /etc/passwd.gateway && \
    printf 'gateway:x:1000:\n' > /etc/group.gateway

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
      export GIT_CONFIG_COUNT=1 \
             GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/GIT_AUTH_TOKEN)@github.com/.insteadOf" \
             GIT_CONFIG_VALUE_0="https://github.com/"; \
    fi; \
    CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build

# Stage 2: Runtime image
# THE IMAGE IS THE BINARY.
#
# The gateway is one statically linked Go binary — CGO_ENABLED=0 above, so it
# takes nothing from a host at run time. Everything the Alpine base was supplying
# was either INERT DATA the binary reads (the trust bundle, the zone database) or
# a file the kernel reads to answer "who is this uid" (/etc/passwd), and all of
# those copy. What is left of a distribution — musl, busybox, the dynamic linker,
# apk — was never executed by anything here, and each carries its own upstream and
# its own CVE feed.
#
# The one thing that genuinely needed an executable was the HEALTHCHECK, which
# shelled out to wget. It is gone rather than replaced: every deployment of this
# image runs under Kubernetes, whose readinessProbe and livenessProbe do the same
# job from outside the container (universe charts/app workload.yaml), and nothing
# in this repository declares a compose dependency on service_healthy. Keeping a
# shell so the image can ask itself a question the orchestrator already asks is
# the whole distroless trade, made backwards.
FROM scratch

LABEL maintainer="dev@hanzo.ai"

# The trust bundle and the zone database: data, read by the binary, executed by
# nothing. tzdata is copied rather than embedded with time/tzdata so the image
# stays a build concern and the source does not change.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# The account the process runs as. There is no adduser on scratch, so the two
# files it would have written are written here instead — the uid is what the
# kernel enforces, and /etc/passwd only lets something later put a name to it.
COPY --from=builder /etc/passwd.gateway /etc/passwd
COPY --from=builder /etc/group.gateway /etc/group

COPY --from=builder /app/gateway /usr/bin/gateway

ARG CONFIG=hanzo
COPY configs/${CONFIG}/gateway.json /etc/gateway/gateway.json

USER 1000:1000
WORKDIR /etc/gateway
ENTRYPOINT [ "/usr/bin/gateway" ]
CMD [ "run", "-c", "/etc/gateway/gateway.json" ]
EXPOSE 8080 8090
