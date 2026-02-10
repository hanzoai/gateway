.PHONY: help build-hanzo build-lux deploy-hanzo deploy-lux apply-hanzo apply-lux validate

KRAKEND_IMAGE ?= devopsfaith/krakend:2.5

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

## Validation

validate: ## Validate all KrakenD configs
	docker run --rm -v $(PWD)/configs/hanzo:/etc/krakend $(KRAKEND_IMAGE) check -c /etc/krakend/krakend.json
	docker run --rm -v $(PWD)/configs/lux:/etc/krakend $(KRAKEND_IMAGE) check -c /etc/krakend/krakend.json

## Hanzo cluster (hanzo-k8s)

apply-hanzo: ## Apply hanzo gateway config to k8s
	kubectl --context do-sfo3-hanzo-k8s -n hanzo create configmap krakend-config --from-file=krakend.json=configs/hanzo/krakend.json --dry-run=client -o yaml | kubectl --context do-sfo3-hanzo-k8s apply -f -
	kubectl --context do-sfo3-hanzo-k8s apply -f k8s/hanzo/
	kubectl --context do-sfo3-hanzo-k8s -n hanzo rollout restart deployment krakend

deploy-hanzo: apply-hanzo ## Deploy hanzo gateway (alias for apply-hanzo)

## Lux cluster (lux-k8s)

apply-lux: ## Apply lux gateway config to k8s
	kubectl --context do-sfo3-lux-k8s -n lux-gateway create configmap krakend-config --from-file=krakend.json=configs/lux/krakend.json --dry-run=client -o yaml | kubectl --context do-sfo3-lux-k8s apply -f -
	kubectl --context do-sfo3-lux-k8s apply -f k8s/lux/
	kubectl --context do-sfo3-lux-k8s -n lux-gateway rollout restart deployment krakend

deploy-lux: apply-lux ## Deploy lux gateway (alias for apply-lux)

## Deploy all

deploy: deploy-hanzo deploy-lux ## Deploy to both clusters

## Status

status: ## Show gateway status on both clusters
	@echo "=== Hanzo Gateway ==="
	kubectl --context do-sfo3-hanzo-k8s -n hanzo get deployment krakend
	kubectl --context do-sfo3-hanzo-k8s -n hanzo get pods -l app=krakend
	@echo ""
	@echo "=== Lux Gateway ==="
	kubectl --context do-sfo3-lux-k8s -n lux-gateway get deployment krakend
	kubectl --context do-sfo3-lux-k8s -n lux-gateway get pods -l app=krakend

logs-hanzo: ## Tail hanzo gateway logs
	kubectl --context do-sfo3-hanzo-k8s -n hanzo logs -l app=krakend -f --tail=50

logs-lux: ## Tail lux gateway logs
	kubectl --context do-sfo3-lux-k8s -n lux-gateway logs -l app=krakend -f --tail=50
