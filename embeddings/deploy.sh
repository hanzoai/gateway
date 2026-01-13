#!/bin/bash
set -e

# Hanzo Embeddings API - Deployment Script
# Deploys to DigitalOcean droplet

IMAGE="hanzoai/embeddings:latest"
CONTAINER="hanzo-embeddings"
PORT=3002
DROPLET="hanzo-embeddings"

echo "🧠 Deploying Hanzo Embeddings API"
echo ""

# Build multi-platform image
echo "📦 Building Docker image..."
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t $IMAGE \
  --push \
  .

echo "✅ Image pushed to Docker Hub: $IMAGE"
echo ""

# Check if droplet exists
if ! doctl compute droplet list --format Name --no-header | grep -q "^${DROPLET}$"; then
  echo "🖥️  Creating droplet: $DROPLET"
  doctl compute droplet create $DROPLET \
    --region sfo3 \
    --size s-1vcpu-1gb \
    --image docker-20-04 \
    --ssh-keys $(doctl compute ssh-key list --format ID --no-header | head -1) \
    --wait

  echo "⏳ Waiting for droplet to be ready..."
  sleep 30
fi

# Get droplet IP
DROPLET_IP=$(doctl compute droplet list --format Name,PublicIPv4 --no-header | grep "^${DROPLET}" | awk '{print $2}')
echo "🌐 Droplet IP: $DROPLET_IP"

# Deploy container
echo "🚀 Deploying container..."
doctl compute ssh $DROPLET --ssh-command "
  docker pull $IMAGE
  docker stop $CONTAINER 2>/dev/null || true
  docker rm $CONTAINER 2>/dev/null || true
  docker run -d \
    --name $CONTAINER \
    --restart unless-stopped \
    -p $PORT:$PORT \
    -e OPENAI_API_KEY='${OPENAI_API_KEY:-}' \
    -e DEFAULT_EMBEDDING_MODEL='text-embedding-3-small' \
    $IMAGE
"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🏥 Health: http://$DROPLET_IP:$PORT/health"
echo "📊 Models: http://$DROPLET_IP:$PORT/v1/models"
echo "🧠 Embed:  POST http://$DROPLET_IP:$PORT/v1/embeddings"
echo ""
echo "📌 Configure DNS: embeddings.hanzo.ai → $DROPLET_IP"
