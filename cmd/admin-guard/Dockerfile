# syntax=docker/dockerfile:1
# admin-guard — the single forward-auth gate for Hanzo's raw global-admin
# surfaces. Tiny static Go binary; reuses github.com/hanzoai/gateway/v2/iamauth.
ARG GOLANG_VERSION=1.26.5
ARG ALPINE_VERSION=3.23

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} AS builder
ARG TARGETOS TARGETARCH

RUN apk --no-cache add git

COPY . /app
WORKDIR /app

# Private cross-repo modules are fetched via authenticated git (gh_token secret),
# bypassing the public proxy + checksum DB — matches the gateway Dockerfile.
ENV GOPRIVATE=github.com/hanzoai/*,github.com/lux-private/*,github.com/zap-proto/*

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=gh_token \
    if [ -s /run/secrets/gh_token ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags="-s -w" -o /admin-guard ./cmd/admin-guard

FROM alpine:${ALPINE_VERSION}
LABEL maintainer="dev@hanzo.ai"
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata wget && \
    adduser -u 1000 -S -D -H guard
COPY --from=builder /admin-guard /usr/bin/admin-guard
USER 1000
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/__guard/healthz || exit 1
ENTRYPOINT ["/usr/bin/admin-guard"]
