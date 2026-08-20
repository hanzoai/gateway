# syntax=docker/dockerfile:1
# waitlist-guard — the single forward-auth gate for Hanzo's WAITLIST lockdown.
# Restricts product surfaces to APPROVED identities (IAM approved-flag /
# object.User.IsApproved); waitlisted callers are bounced to the viral waitlist
# (browser) or 403'd (API). Tiny static Go binary; reuses
# github.com/hanzoai/gateway/v2/iamauth.
ARG GOLANG_VERSION=1.26.5
ARG ALPINE_VERSION=3.23

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} AS builder
ARG TARGETOS TARGETARCH

RUN apk --no-cache add git

COPY . /app
WORKDIR /app

# Private cross-repo modules are fetched via authenticated git (gh_token secret).
# Everything else resolves through the public proxy and is verified against
# sum.golang.org — matches the gateway Dockerfile.
ENV GOPRIVATE=github.com/hanzoai/*

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=gh_token \
    if [ -s /run/secrets/gh_token ]; then \
      export GIT_CONFIG_COUNT=1 \
             GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/gh_token)@github.com/.insteadOf" \
             GIT_CONFIG_VALUE_0="https://github.com/"; \
    fi; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags="-s -w" -o /waitlist-guard ./cmd/waitlist-guard

FROM alpine:${ALPINE_VERSION}
LABEL maintainer="dev@hanzo.ai"
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata wget && \
    adduser -u 1000 -S -D -H guard
COPY --from=builder /waitlist-guard /usr/bin/waitlist-guard
USER 1000
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/__guard/healthz || exit 1
ENTRYPOINT ["/usr/bin/waitlist-guard"]
