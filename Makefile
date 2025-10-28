.PHONY: help deploy setup-do build push run stop logs clean test

# Configuration
IMAGE_NAME := hanzoai/gateway
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
DO_DROPLET_NAME := hanzo-gateway
DO_SIZE := s-1vcpu-1gb
DO_REGION := nyc1
DO_IMAGE := docker-20-04

help:
	@echo "Hanzo Gateway Deployment"
	@echo ""
	@echo "Quick Start:"
	@echo "  make deploy             - Deploy to DigitalOcean (one command)"
	@echo ""
	@echo "Docker Commands:"
	@echo "  make build              - Build Docker image locally"
	@echo "  make push               - Push to Docker Hub"
	@echo "  make run                - Run locally with docker-compose"
	@echo "  make stop               - Stop local containers"
	@echo "  make logs               - View logs"
	@echo ""
	@echo "DigitalOcean Commands:"
	@echo "  make setup-do           - Create DigitalOcean droplet"
	@echo "  make ssh-do             - SSH into droplet"
	@echo "  make status             - Check deployment status"
	@echo "  make destroy-do         - Destroy droplet"
	@echo ""
	@echo "Development:"
	@echo "  make test               - Run tests"
	@echo "  make clean              - Clean up"

# Build Docker image
build:
	@echo "Building $(IMAGE_NAME):$(VERSION)..."
	docker build -f docker/Dockerfile.prebuilt -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .
	@echo "✅ Built $(IMAGE_NAME):$(VERSION)"

# Push to Docker Hub
push: build
	@echo "Pushing $(IMAGE_NAME):$(VERSION)..."
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest
	@echo "✅ Pushed to Docker Hub"

# Run locally
run:
	@echo "Starting gateway locally..."
	docker-compose up -d
	@echo "✅ Gateway running at http://localhost:9550"
	@echo "Health check: curl http://localhost:9550/health"

# Stop local containers
stop:
	@echo "Stopping gateway..."
	docker-compose down
	@echo "✅ Stopped"

# View logs
logs:
	docker-compose logs -f

# Run tests
test:
	@echo "Running tests..."
	cd gateway && npm test
	@echo "✅ Tests passed"

# Clean up
clean:
	@echo "Cleaning up..."
	docker-compose down -v
	docker system prune -f
	@echo "✅ Cleaned"

#==============================================================================
# DigitalOcean Deployment
#==============================================================================

# Create DigitalOcean droplet
setup-do:
	@echo "Creating DigitalOcean droplet..."
	@command -v doctl >/dev/null 2>&1 || { echo "❌ doctl not installed. Run: brew install doctl"; exit 1; }
	@echo "Checking if droplet exists..."
	@if doctl compute droplet list --format Name | grep -q "^$(DO_DROPLET_NAME)$$"; then \
		echo "✅ Droplet $(DO_DROPLET_NAME) already exists"; \
	else \
		echo "Creating new droplet $(DO_DROPLET_NAME)..."; \
		doctl compute droplet create $(DO_DROPLET_NAME) \
			--size $(DO_SIZE) \
			--image $(DO_IMAGE) \
			--region $(DO_REGION) \
			--ssh-keys $$(doctl compute ssh-key list --format ID --no-header | head -1) \
			--wait; \
		echo "✅ Droplet created"; \
	fi
	@echo ""
	@echo "Droplet IP:"
	@doctl compute droplet list --format Name,PublicIPv4 | grep $(DO_DROPLET_NAME)

# Get droplet IP
do-ip:
	@doctl compute droplet list --format Name,PublicIPv4 --no-header | grep "^$(DO_DROPLET_NAME)" | awk '{print $$2}'

# SSH into droplet
ssh-do:
	@echo "SSHing into $(DO_DROPLET_NAME)..."
	@ssh root@$$(make -s do-ip)

# Deploy to DigitalOcean droplet
deploy-do:
	@echo "Deploying gateway to DigitalOcean..."
	@command -v doctl >/dev/null 2>&1 || { echo "❌ doctl not installed. Run: brew install doctl"; exit 1; }

	@# Get droplet IP
	$(eval DROPLET_IP := $(shell make -s do-ip))
	@if [ -z "$(DROPLET_IP)" ]; then \
		echo "❌ Droplet $(DO_DROPLET_NAME) not found. Run: make setup-do"; \
		exit 1; \
	fi

	@echo "Deploying to $(DROPLET_IP)..."

	@# Create deployment script
	@echo '#!/bin/bash' > /tmp/deploy-gateway.sh
	@echo 'set -e' >> /tmp/deploy-gateway.sh
	@echo '' >> /tmp/deploy-gateway.sh
	@echo 'echo "🚀 Deploying Hanzo Gateway..."' >> /tmp/deploy-gateway.sh
	@echo '' >> /tmp/deploy-gateway.sh
	@echo '# Install Docker if not present' >> /tmp/deploy-gateway.sh
	@echo 'if ! command -v docker &> /dev/null; then' >> /tmp/deploy-gateway.sh
	@echo '  echo "Installing Docker..."' >> /tmp/deploy-gateway.sh
	@echo '  curl -fsSL https://get.docker.com | sh' >> /tmp/deploy-gateway.sh
	@echo '  systemctl enable docker' >> /tmp/deploy-gateway.sh
	@echo '  systemctl start docker' >> /tmp/deploy-gateway.sh
	@echo 'fi' >> /tmp/deploy-gateway.sh
	@echo '' >> /tmp/deploy-gateway.sh
	@echo '# Pull latest image' >> /tmp/deploy-gateway.sh
	@echo 'echo "Pulling $(IMAGE_NAME):latest..."' >> /tmp/deploy-gateway.sh
	@echo 'docker pull $(IMAGE_NAME):latest' >> /tmp/deploy-gateway.sh
	@echo '' >> /tmp/deploy-gateway.sh
	@echo '# Stop existing container' >> /tmp/deploy-gateway.sh
	@echo 'docker stop hanzo-gateway 2>/dev/null || true' >> /tmp/deploy-gateway.sh
	@echo 'docker rm hanzo-gateway 2>/dev/null || true' >> /tmp/deploy-gateway.sh
	@echo '' >> /tmp/deploy-gateway.sh
	@echo '# Start new container' >> /tmp/deploy-gateway.sh
	@echo 'echo "Starting gateway..."' >> /tmp/deploy-gateway.sh
	@echo 'docker run -d \' >> /tmp/deploy-gateway.sh
	@echo '  --name hanzo-gateway \' >> /tmp/deploy-gateway.sh
	@echo '  --restart unless-stopped \' >> /tmp/deploy-gateway.sh
	@echo '  -p 80:9550 \' >> /tmp/deploy-gateway.sh
	@echo '  -p 9550:9550 \' >> /tmp/deploy-gateway.sh
	@echo '  -e GLOBAL_IDENTITY_NAME=did:hanzo:gateway \' >> /tmp/deploy-gateway.sh
	@echo '  -e NODE_API_PORT=9550 \' >> /tmp/deploy-gateway.sh
	@echo '  $(IMAGE_NAME):latest' >> /tmp/deploy-gateway.sh
	@echo '' >> /tmp/deploy-gateway.sh
	@echo 'echo "✅ Gateway deployed successfully!"' >> /tmp/deploy-gateway.sh
	@echo 'echo ""' >> /tmp/deploy-gateway.sh
	@echo 'echo "Gateway URL: http://$(DROPLET_IP)"' >> /tmp/deploy-gateway.sh
	@echo 'echo "Health check: curl http://$(DROPLET_IP)/health"' >> /tmp/deploy-gateway.sh
	@echo 'echo ""' >> /tmp/deploy-gateway.sh
	@echo 'docker ps -a | grep hanzo-gateway' >> /tmp/deploy-gateway.sh

	@chmod +x /tmp/deploy-gateway.sh

	@# Copy and execute deployment script
	@scp -o StrictHostKeyChecking=no /tmp/deploy-gateway.sh root@$(DROPLET_IP):/tmp/
	@ssh -o StrictHostKeyChecking=no root@$(DROPLET_IP) 'bash /tmp/deploy-gateway.sh'

	@echo ""
	@echo "✅ Deployment complete!"
	@echo ""
	@echo "Gateway URL: http://$(DROPLET_IP)"
	@echo "Health check: curl http://$(DROPLET_IP)/health"
	@echo ""
	@echo "View logs: make logs-do"
	@echo "SSH access: make ssh-do"

# View droplet logs
logs-do:
	@ssh root@$$(make -s do-ip) 'docker logs -f hanzo-gateway'

# Destroy droplet
destroy-do:
	@echo "⚠️  WARNING: This will destroy the $(DO_DROPLET_NAME) droplet!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Destroying droplet..."; \
		doctl compute droplet delete $(DO_DROPLET_NAME) --force; \
		echo "✅ Droplet destroyed"; \
	else \
		echo "Cancelled"; \
	fi

#==============================================================================
# Quick Deployment (One Command)
#==============================================================================

# Main deployment command: create droplet + deploy gateway
deploy:
	@echo "🚀 Deploying Hanzo Gateway to DigitalOcean..."
	@make setup-do
	@echo "Waiting 30 seconds for droplet to initialize..."
	@sleep 30
	@make deploy-do
	@echo ""
	@echo "✅ Deployment complete!"
	@echo "Gateway URL: http://$$(make -s do-ip)"

# Alias for deploy
deploy-full: deploy

#==============================================================================
# Status & Monitoring
#==============================================================================

# Check status
status: status-do
status-do:
	@echo "Checking gateway status on DigitalOcean..."
	@ssh root@$$(make -s do-ip) 'docker ps | grep hanzo-gateway'
	@echo ""
	@echo "Health check:"
	@curl -s http://$$(make -s do-ip)/health | jq . || echo "❌ Gateway not responding"

# Update gateway (redeploy)
update-do:
	@echo "Updating gateway on DigitalOcean..."
	@make deploy-do
