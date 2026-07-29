.PHONY: all build test help deploy deploy-hanzo deploy-lux apply-hanzo apply-lux validate status clean docker

BIN_NAME := gateway
OS := $(shell uname | tr '[:upper:]' '[:lower:]')
MODULE := github.com/hanzoai/gateway
VERSION := 2.13.0
SCHEMA_VERSION := $(shell echo "${VERSION}" | cut -d '.' -f 1,2)
GIT_COMMIT = $(shell git rev-parse --short=7 HEAD 2>/dev/null)
GOLANG_VERSION := 1.26.3
ALPINE_VERSION := 3.23
GLIBC_VERSION := $(shell sh find_glibc.sh 2>/dev/null || echo "unknown")

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

## Build

all: test

# BUILD_TAGS selects the gateway entrypoint. The production HTTP edge runs
# the legacy `run -c gateway.json` path (cmd/gateway/main_legacy.go, tag
# `legacy`) which mounts NewEngine -> hostProxyMiddleware (the proven HTTP
# relay of api.hanzo.ai /v1/* straight to cloud-api:8000) + the CORS
# preflight allowlist. The default (untagged) main.go is the HIP-0110
# pure ZAP->ZAP relay; it serves ONLY /healthz on :8080 and 404s every
# model call when the ZAP backends are absent (they are: cloud:9090 is
# cloud's health listener, the base service does not exist). Until the
# ZAP relay backends are live (HIP-0110 Phase C), the edge MUST be the
# `legacy` build — that is what the Dockerfile CMD (`run -c ...`) drives.
BUILD_TAGS ?= legacy

# CORE is the vendored engine's core package — the home of the version vars the
# binary stamps at link time. Folding the engine in (internal/lura) moved these
# off the upstream module path; an -X against a symbol that does not exist is
# silently ignored by the linker, so a stale path here would ship an "undefined"
# version in the User-Agent and X-Api-Version with no build error.
CORE := ${MODULE}/v2/internal/lura/core

build: ## Build the gateway binary (legacy HTTP edge; BUILD_TAGS=legacy)
	@echo "Building the gateway binary (tags: ${BUILD_TAGS})..."
	@go build -mod=readonly -tags "${BUILD_TAGS}" -ldflags="-X ${CORE}.KrakendVersion=${VERSION} \
	-X ${CORE}.GlibcVersion=${GLIBC_VERSION}" \
	-o ${BIN_NAME} ./cmd/gateway
	@echo "You can now use ./${BIN_NAME}"

build-ingress: ## Build the ingress binary
	@echo "Building the ingress binary..."
	@CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=${VERSION}" -o ingress ./cmd/ingress
	@echo "You can now use ./ingress"

test: build ## Build and run tests
	go test -mod=readonly -tags "${BUILD_TAGS}" -v ./tests

# cmd/gateway/schema/schema.json is COMMITTED, not fetched.
#
# It used to be gitignored and pulled at build time from a namespace we do not
# control (raw.githubusercontent.com/krakend/krakend-schema, with a plain-HTTPS
# fallback to a vendor site) with no checksum of any kind, then //go:embed-ed
# into the shipping binary. That is the same supply-chain exposure as an
# unpinned module import, minus go.sum: whatever that host served became the
# schema `gateway check` validates every production config against, so a
# poisoned schema could wave through an insecure config.
#
# The artifact is ours anyway — the rebranding pass below rewrote every URL and
# brand string in it — so it is now a reviewable, version-controlled file. Run
# `make schema` deliberately to refresh it from upstream and review the diff.
.PHONY: schema
schema: ## Refresh the embedded config schema from upstream (review the diff!)
	@echo "Fetching v${SCHEMA_VERSION} schema"
	@wget -qO cmd/gateway/schema/schema.json.orig https://raw.githubusercontent.com/krakend/krakend-schema/refs/heads/main/v${SCHEMA_VERSION}/krakend.json
	@echo "Rebranding embedded schema descriptions and URLs"
	@sed \
		-e 's|https://www.krakend.io|https://gateway.hanzo.ai|g' \
		-e 's|https://krakend.io|https://gateway.hanzo.ai|g' \
		-e 's|www.krakend.io|gateway.hanzo.ai|g' \
		-e 's|krakend.io|gateway.hanzo.ai|g' \
		-e 's|KrakenD Enterprise|Hanzo Gateway Enterprise|g' \
		-e 's|KrakenD|Gateway|g' \
		-e 's|Krakend|Gateway|g' \
		-e 's|KRAKEND|GATEWAY|g' \
		-e 's|krakend|gateway|g' \
		cmd/gateway/schema/schema.json.orig > cmd/gateway/schema/schema.json
	@rm -f cmd/gateway/schema/schema.json.orig
	@echo "Review: git diff cmd/gateway/schema/schema.json"

REGISTRY := ghcr.io/hanzoai/gateway

docker: ## Build Docker image
	docker build --no-cache --pull --build-arg GOLANG_VERSION=${GOLANG_VERSION} --build-arg ALPINE_VERSION=${ALPINE_VERSION} \
		-t ${REGISTRY}:${VERSION} -t ${REGISTRY}:latest .

docker-hanzo: ## Build hanzo config Docker image
	docker build --build-arg CONFIG=hanzo \
		-t ${REGISTRY}:latest \
		-t ${REGISTRY}:v${VERSION} \
		-t ${REGISTRY}:v${VERSION}-${GIT_COMMIT} .

docker-lux: ## Build lux config Docker image
	docker build --build-arg CONFIG=lux \
		-t ${REGISTRY}:lux-latest \
		-t ${REGISTRY}:lux-v${VERSION} .

docker-push: ## Push all tags to registry
	docker push ${REGISTRY} --all-tags

docker-push-hanzo: docker-hanzo ## Build and push hanzo gateway
	docker push ${REGISTRY}:latest
	docker push ${REGISTRY}:v${VERSION}
	docker push ${REGISTRY}:v${VERSION}-${GIT_COMMIT}

## Validation

validate: ## Validate all configs
	./$(BIN_NAME) check -c configs/hanzo/gateway.json
	./$(BIN_NAME) check -c configs/lux/gateway.json

## Hanzo cluster (hanzo-k8s)

apply-hanzo: ## Apply hanzo gateway config to k8s
	kubectl --context do-sfo3-hanzo-k8s -n hanzo create configmap gateway-config --from-file=gateway.json=configs/hanzo/gateway.json --dry-run=client -o yaml | kubectl --context do-sfo3-hanzo-k8s apply -f -
	kubectl --context do-sfo3-hanzo-k8s apply -f k8s/hanzo/
	kubectl --context do-sfo3-hanzo-k8s -n hanzo rollout restart deployment gateway

apply-ingress-hanzo: ## Apply hanzo ingress to k8s
	kubectl --context do-sfo3-hanzo-k8s -n hanzo create configmap ingress-config --from-file=ingress.json=configs/hanzo/ingress.json --dry-run=client -o yaml | kubectl --context do-sfo3-hanzo-k8s apply -f -
	kubectl --context do-sfo3-hanzo-k8s apply -f k8s/hanzo-ingress/
	kubectl --context do-sfo3-hanzo-k8s -n hanzo rollout restart deployment hanzo-ingress

deploy-ingress-hanzo: apply-ingress-hanzo ## Deploy hanzo ingress (alias)

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
