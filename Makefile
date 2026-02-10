.PHONY: all build test help deploy deploy-hanzo deploy-lux apply-hanzo apply-lux validate status clean docker

BIN_NAME := gateway
OS := $(shell uname | tr '[:upper:]' '[:lower:]')
MODULE := github.com/hanzoai/gateway/v2
VERSION := 2.12.1
SCHEMA_VERSION := $(shell echo "${VERSION}" | cut -d '.' -f 1,2)
GIT_COMMIT := $(shell git rev-parse --short=7 HEAD)
GOLANG_VERSION := 1.25.6
ALPINE_VERSION := 3.23
GLIBC_VERSION := $(shell sh find_glibc.sh 2>/dev/null || echo "unknown")

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

## Build

all: test

build: cmd/gateway/schema/schema.json ## Build the gateway binary
	@echo "Building the gateway binary..."
	@go get .
	@go build -ldflags="-X ${MODULE}/pkg.Version=${VERSION} -X github.com/luraproject/lura/v2/core.KrakendVersion=${VERSION} \
	-X github.com/luraproject/lura/v2/core.GlibcVersion=${GLIBC_VERSION}" \
	-o ${BIN_NAME} ./cmd/gateway
	@echo "You can now use ./${BIN_NAME}"

test: build ## Build and run tests
	go test -v ./tests

cmd/gateway/schema/schema.json:
	@echo "Fetching v${SCHEMA_VERSION} schema"
	@wget -qO $@ https://raw.githubusercontent.com/krakend/krakend-schema/refs/heads/main/v${SCHEMA_VERSION}/krakend.json || wget -qO $@ https://krakend.io/schema/krakend.json

docker: ## Build Docker image
	docker build --no-cache --pull --build-arg GOLANG_VERSION=${GOLANG_VERSION} --build-arg ALPINE_VERSION=${ALPINE_VERSION} -t hanzoai/gateway:${VERSION} .

docker-hanzo: ## Build hanzo config Docker image
	docker build --build-arg CONFIG=hanzo -t hanzoai/gateway:hanzo-latest .

docker-lux: ## Build lux config Docker image
	docker build --build-arg CONFIG=lux -t hanzoai/gateway:lux-latest .

## Validation

validate: ## Validate all configs
	./$(BIN_NAME) check -c configs/hanzo/gateway.json
	./$(BIN_NAME) check -c configs/lux/gateway.json

## Hanzo cluster (hanzo-k8s)

apply-hanzo: ## Apply hanzo gateway config to k8s
	kubectl --context do-sfo3-hanzo-k8s -n hanzo create configmap gateway-config --from-file=gateway.json=configs/hanzo/gateway.json --dry-run=client -o yaml | kubectl --context do-sfo3-hanzo-k8s apply -f -
	kubectl --context do-sfo3-hanzo-k8s apply -f k8s/hanzo/
	kubectl --context do-sfo3-hanzo-k8s -n hanzo rollout restart deployment gateway

deploy-hanzo: apply-hanzo ## Deploy hanzo gateway (alias for apply-hanzo)

## Lux cluster (lux-k8s)

apply-lux: ## Apply lux gateway config to k8s
	kubectl --context do-sfo3-lux-k8s -n lux-gateway create configmap gateway-config --from-file=gateway.json=configs/lux/gateway.json --dry-run=client -o yaml | kubectl --context do-sfo3-lux-k8s apply -f -
	kubectl --context do-sfo3-lux-k8s apply -f k8s/lux/
	kubectl --context do-sfo3-lux-k8s -n lux-gateway rollout restart deployment gateway

deploy-lux: apply-lux ## Deploy lux gateway (alias for apply-lux)

## Deploy all

deploy: deploy-hanzo deploy-lux ## Deploy to both clusters

## Status

status: ## Show gateway status on both clusters
	@echo "=== Hanzo Gateway ==="
	kubectl --context do-sfo3-hanzo-k8s -n hanzo get deployment gateway
	kubectl --context do-sfo3-hanzo-k8s -n hanzo get pods -l app=gateway
	@echo ""
	@echo "=== Lux Gateway ==="
	kubectl --context do-sfo3-lux-k8s -n lux-gateway get deployment gateway
	kubectl --context do-sfo3-lux-k8s -n lux-gateway get pods -l app=gateway

logs-hanzo: ## Tail hanzo gateway logs
	kubectl --context do-sfo3-hanzo-k8s -n hanzo logs -l app=gateway -f --tail=50

logs-lux: ## Tail lux gateway logs
	kubectl --context do-sfo3-lux-k8s -n lux-gateway logs -l app=gateway -f --tail=50

clean: ## Clean build artifacts
	rm -rf builder/skel/*
	rm -f ${BIN_NAME}
	rm -rf vendor/
	rm -f cmd/gateway/schema/schema.json
