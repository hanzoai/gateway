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

build: cmd/gateway/schema/schema.json vendor-rebrand ## Build the gateway binary with rebranded vendored deps
	@echo "Building the gateway binary (vendor mode, rebranded)..."
	@go build -mod=vendor -ldflags="-X ${MODULE}/pkg.Version=${VERSION} -X github.com/luraproject/lura/v2/core.KrakendVersion=${VERSION} \
	-X github.com/luraproject/lura/v2/core.GlibcVersion=${GLIBC_VERSION}" \
	-o ${BIN_NAME} ./cmd/gateway
	@echo "You can now use ./${BIN_NAME}"

# vendor-rebrand vendors every dependency, then rewrites every user-visible
# kraken string literal in telemetry/metrics/audit modules so the runtime
# output (OTEL attributes, Prometheus metric names, X-Ray/OCAgent service
# names) carries the Hanzo brand instead. Third-party package paths under
# github.com/krakend/* and github.com/devopsfaith/* remain intact — they are
# plugin-registry internals, never emitted to users.
vendor-rebrand: vendor ## Rebrand user-visible kraken strings in vendored telemetry/metrics modules
	@echo "Rebranding runtime-visible kraken strings in vendored deps"
	@# Module-wide aggressive rebrand: rewrite every user-visible KrakenD/Krakend/KRAKEND
	@# string literal in upstream modules. Import paths under github.com/krakend/*
	@# and github.com/devopsfaith/* stay intact; those are plugin registry
	@# internals. We only touch quoted and backtick string content inside the
	@# upstream telemetry/metrics/CLI/helper packages.
	@find vendor/github.com/krakend \
	      -name "*.go" -type f 2>/dev/null \
	  | xargs -I{} sed -i.bak \
	      -e 's|"krakend\.|"gateway\.|g' \
	      -e 's|"krakend-|"gateway-|g' \
	      -e 's|"krakendrate\.|"gatewayrate\.|g' \
	      -e 's|`krakend\\.|`gateway\\.|g' \
	      -e 's|"KrakenD-Opencensus"|"Gateway-Opentelemetry"|g' \
	      -e 's|"KrakenD-opencensus"|"Gateway-opentelemetry"|g' \
	      -e 's|"KrakenD "|"Gateway "|g' \
	      -e 's|"KrakenD\\.|"Gateway\\.|g' \
	      -e 's|"KrakenD_|"Gateway_|g' \
	      -e 's|"KrakenD-|"Gateway-|g' \
	      -e 's|"KrakenD Version:"|"Gateway Version:"|g' \
	      -e 's|"KRAKEND_"|"GATEWAY_"|g' \
	      -e 's|KrakenD is a high-performance API gateway that helps you publish, secure, control, and monitor your services|hanzoai/gateway is a Hanzo API gateway that helps you publish, secure, control, and monitor your services|g' \
	      -e 's|Runs the KrakenD server.|Runs the Gateway server.|g' \
	      -e 's|Shows KrakenD version.|Shows Gateway version.|g' \
	      -e 's|Audits a KrakenD configuration.|Audits a Gateway configuration.|g' \
	      -e 's|Enables the linting against the official KrakenD online JSON schema|Enables the linting against the official Gateway online JSON schema|g' \
	      -e 's|Lint against the builtin Krakend JSON schema|Lint against the builtin Gateway JSON schema|g' \
	      -e 's|Information about how KrakenD is interpreting|Information about how Gateway is interpreting|g' \
	      -e 's|"https://www.krakend.io/schema/v%s/krakend.json"|"https://gateway.hanzo.ai/schema/v%s/gateway.json"|g' \
	      -e 's|krakend check -d -l -c config.json|gateway check -d -l -c config.json|g' \
	      -e 's|krakend run -d -c config.json|gateway run -d -c config.json|g' \
	      -e 's|krakend check-plugin -g 1.19.0 -s ./go.sum -f|gateway check-plugin -g 1.19.0 -s ./go.sum -f|g' \
	      -e 's|krakend version|gateway version|g' \
	      -e 's|krakend audit -i 1.1.1,1.1.2 -s CRITICAL -c krakend.json|gateway audit -i 1.1.1,1.1.2 -s CRITICAL -c gateway.json|g' \
	      -e 's|Krakend-opencensus|Gateway-opentelemetry|g' \
	      -e 's|KrakendD-Context-OTEL|Gateway-Context-OTEL|g' \
	      {}
	@# Patch the upstream cobra logo so the banner shows our brand at runtime too.
	@sed -i.bak \
	      -e 's|Use:   "krakend"|Use:   "gateway"|g' \
	      vendor/github.com/krakend/krakend-cobra/v2/root.go 2>/dev/null || true
	@# Replace the static ASCII logo encoded constant so the banner bytes are not
	@# embedded in the binary.
	@sed -i.bak \
	      -e 's|const encodedLogo = "[^"]*"|const encodedLogo = ""|' \
	      vendor/github.com/krakend/krakend-cobra/v2/root.go 2>/dev/null || true
	@# Flip "KrakenD Version:" literal in versionFunc.
	@sed -i.bak \
	      -e 's|cmd.Println("KrakenD Version:"|cmd.Println("hanzoai/gateway Version:"|g' \
	      vendor/github.com/krakend/krakend-cobra/v2/version.go 2>/dev/null || true
	@# Flexibleconfig temp file prefix.
	@sed -i.bak \
	      -e 's|"KrakenD_parsed_config_template_"|"gateway_parsed_config_template_"|g' \
	      vendor/github.com/krakend/krakend-flexibleconfig/v2/template.go 2>/dev/null || true
	@find vendor -name "*.bak" -delete 2>/dev/null || true

vendor: ## Vendor dependencies for hermetic rebrand-able builds
	@go mod vendor

build-ingress: ## Build the ingress binary
	@echo "Building the ingress binary..."
	@CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=${VERSION}" -o ingress ./cmd/ingress
	@echo "You can now use ./ingress"

test: build ## Build and run tests
	go test -v ./tests

cmd/gateway/schema/schema.json:
	@echo "Fetching v${SCHEMA_VERSION} schema"
	@wget -qO $@.orig https://raw.githubusercontent.com/krakend/krakend-schema/refs/heads/main/v${SCHEMA_VERSION}/krakend.json || wget -qO $@.orig https://krakend.io/schema/krakend.json
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
		$@.orig > $@
	@rm -f $@.orig

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
	rm -f cmd/gateway/schema/schema.json
