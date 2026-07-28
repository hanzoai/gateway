# syntax=docker/dockerfile:1
# admin-api — god-mode backend for the Hanzo Operator console (admin.hanzo.ai).
# Aggregates every product into the ZAP-native datastore and serves the
# superadmin-gated /v1/admin/* read API. Reuses github.com/hanzoai/gateway/v2
# iamauth + github.com/hanzoai/datastore-go/v2.
ARG GOLANG_VERSION=1.26.5
ARG ALPINE_VERSION=3.23

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} AS builder
ARG TARGETOS TARGETARCH

RUN apk --no-cache add git

COPY . /app
WORKDIR /app

# Private cross-repo modules (hanzoai/cloud, hanzoai/datastore-go, luxfi/*) are
# fetched via authenticated git (gh_token secret), bypassing the public proxy.
ENV GOPRIVATE=github.com/hanzoai/*,github.com/luxfi/*,github.com/zap-proto/*

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=gh_token \
    if [ -s /run/secrets/gh_token ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags="-s -w" -o /admin-api ./cmd/admin-api

FROM alpine:${ALPINE_VERSION}
LABEL maintainer="dev@hanzo.ai"
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata wget && \
    adduser -u 1000 -S -D -H adminapi
COPY --from=builder /admin-api /usr/bin/admin-api
USER 1000
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/v1/admin/healthz || exit 1
ENTRYPOINT ["/usr/bin/admin-api"]
