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

# CGO_ENABLED=0 matches the Dockerfile, so `make build` produces the artifact
# that ships instead of one that merely resembles it. It is also the difference
# between building and not building on a mac: cgo there hands the link to clang
# and the target dies with "linker command failed", which reads as a broken
# repo and is a default nobody chose.
build: ## Build the gateway binary (legacy HTTP edge; BUILD_TAGS=legacy)
	@echo "Building the gateway binary (tags: ${BUILD_TAGS})..."
	@CGO_ENABLED=0 go build -mod=readonly -tags "${BUILD_TAGS}" -ldflags="-X ${CORE}.KrakendVersion=${VERSION} \
	-X ${CORE}.GlibcVersion=${GLIBC_VERSION}" \
	-o ${BIN_NAME} ./cmd/gateway
	@echo "You can now use ./${BIN_NAME}"

# ./... , not ./tests — the gate runs every package, tagged the way the binary is
# built. Two ways to run zero tests were live here at once: the target passed no
# ${BUILD_TAGS}, so the `legacy`-tagged fixture suite under tests/ was excluded
# wholesale; and it named ONE directory, so the 20-odd _test.go files in the root
# package (auth, CORS, widget security, production headers, routing) were never
# in scope at all. `./tests` also needs `build` first: the fixture harness spawns
# ./gateway as the system under test.
#
# BOTH halves, for the same reason `go vet` already runs twice: a build tag
# selects a different file set, so one run can only ever gate one of them.
# cmd/gateway/main_test.go is `//go:build !legacy` — TestShutdownGraceFromEnv
# (six cases over the drain window a rollout depends on) and TestEnvOr — and the
# legacy run excludes it, so those tests existed and had never executed. Same
# defect as the fixture suite, one tag over: the whole tree, both ways it builds.
# THREE runs, and the split of the first two is what makes this gate stop
# flaking. `./tests` spawns ./gateway and waits a FIXED 1500ms before probing
# :8080; on a loaded runner that is not enough and every fixture fails with
# connection refused — a startup race that reads exactly like a mass behavioural
# regression. `-gateway_startup_wait` is the harness's own answer to that and
# was only ever passed by .github/workflows/test.yml, never here, so `make test`
# — the command hanzo.yml actually runs in CI — kept the race.
#
# It cannot be one run: `go test ./... -args -flag` forwards the flag to EVERY
# package's binary and the unit packages abort with "flag provided but not
# defined". So the harness is invoked on its own.
TESTS_PKG := ./tests
STARTUP_WAIT ?= 30s
test: build ## Build and run tests (both builds: the legacy edge and the default relay)
	go test -mod=readonly -tags "${BUILD_TAGS}" -count=1 -v $(shell go list -tags "${BUILD_TAGS}" ./... | grep -v '/tests$$')
	go test -mod=readonly -tags "${BUILD_TAGS}" -count=1 ${TESTS_PKG} -args -gateway_startup_wait=${STARTUP_WAIT}
	go test -mod=readonly -count=1 ./...

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
