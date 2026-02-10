ARG GOLANG_VERSION=1.25.6
ARG ALPINE_VERSION=3.23

# Stage 1: Build the gateway binary from source
FROM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} AS builder

RUN apk --no-cache --virtual .build-deps add make gcc musl-dev binutils-gold git wget

COPY . /app
WORKDIR /app

RUN make build

# Stage 2: Runtime image
FROM alpine:${ALPINE_VERSION}

LABEL maintainer="dev@hanzo.ai"

RUN apk upgrade --no-cache --no-interactive && \
    apk add --no-cache ca-certificates tzdata && \
    adduser -u 1000 -S -D -H gateway && \
    mkdir /etc/gateway && \
    echo '{ "version": 3 }' > /etc/gateway/gateway.json

COPY --from=builder /app/gateway /usr/bin/gateway

# Bake in the config for the target cluster
ARG CONFIG=hanzo
COPY configs/${CONFIG}/gateway.json /etc/gateway/gateway.json

USER 1000

WORKDIR /etc/gateway

ENTRYPOINT [ "/usr/bin/gateway" ]
CMD [ "run", "-c", "/etc/gateway/gateway.json" ]

EXPOSE 8080 8090

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/__health || exit 1
