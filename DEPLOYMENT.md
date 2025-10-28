# Hanzo Gateway - DigitalOcean Deployment Guide

## Quick Deploy (One Command)

```bash
# Full setup: create droplet + deploy gateway
make deploy-full

# Or step by step:
make setup-do      # Create droplet
make deploy-do     # Deploy gateway
```

That's it! Gateway will be live at `http://YOUR_DROPLET_IP` in ~2 minutes.

## Prerequisites

### 1. DigitalOcean CLI
```bash
# Install doctl
brew install doctl  # macOS
# or
snap install doctl  # Linux
# or
choco install doctl # Windows

# Authenticate
doctl auth init
# Paste your API token from: https://cloud.digitalocean.com/account/api/tokens
```

### 2. SSH Key
```bash
# Check existing keys
doctl compute ssh-key list

# Or add your SSH key
doctl compute ssh-key create my-key --public-key "$(cat ~/.ssh/id_rsa.pub)"
```

### 3. Docker Hub (Optional - only if building)
```bash
docker login
# Enter: username, password
```

## Deployment Commands

### Initial Setup
```bash
# Clone repository
git clone https://github.com/hanzoai/gateway.git
cd gateway

# Create droplet (one-time)
make setup-do
# Creates s-1vcpu-1gb droplet in NYC1
# Cost: ~$6/month
```

### Deploy Gateway
```bash
# Deploy to droplet
make deploy-do
# - Installs Docker (if needed)
# - Pulls hanzoai/gateway:latest
# - Starts container on port 80 and 9550

# View deployment status
make status-do

# View live logs
make logs-do
```

### Update Gateway
```bash
# Redeploy with latest changes
make update-do

# Or manually:
git pull origin main
make deploy-do
```

## Configuration

### Environment Variables
The gateway uses environment variables for configuration. Set them during deployment:

```bash
# Edit Makefile deploy-do section:
-e GLOBAL_IDENTITY_NAME=did:hanzo:gateway \
-e NODE_API_PORT=9550 \
-e INITIAL_AGENT_API_KEYS=your-api-keys-here
```

### Custom Droplet Size
Edit `Makefile` if you need more resources:

```makefile
DO_SIZE := s-2vcpu-2gb  # $12/month - better performance
DO_SIZE := s-2vcpu-4gb  # $18/month - production ready
```

### Custom Region
```makefile
DO_REGION := sfo3  # San Francisco
DO_REGION := fra1  # Frankfurt
DO_REGION := sgp1  # Singapore
```

## Verification

### Health Check
```bash
# Get droplet IP
make do-ip

# Test health endpoint
curl http://$(make -s do-ip)/health

# Expected response:
{
  "status": "healthy",
  "version": "1.12.0",
  "identity": "did:hanzo:gateway"
}
```

### Test Inference
```bash
# Test chat completions
curl -X POST http://$(make -s do-ip)/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Hello"}],
    "model": "default"
  }'
```

## Monitoring

### View Logs
```bash
# Real-time logs
make logs-do

# Last 100 lines
ssh root@$(make -s do-ip) 'docker logs --tail 100 hanzo-gateway'
```

### Check Resource Usage
```bash
# SSH into droplet
make ssh-do

# View container stats
docker stats hanzo-gateway

# System resources
htop
df -h
```

### Container Status
```bash
make status-do

# Or manually:
ssh root@$(make -s do-ip) 'docker ps -a'
```

## Scaling

### Vertical Scaling (Resize Droplet)
```bash
# Via DigitalOcean Console:
# 1. Go to Droplets → hanzo-gateway
# 2. Click "Resize"
# 3. Select new size
# 4. Resize & Restart

# Or via CLI:
doctl compute droplet-action resize hanzo-gateway \
  --size s-2vcpu-2gb \
  --wait
```

### Horizontal Scaling (Load Balancer)
```bash
# Create load balancer
doctl compute load-balancer create \
  --name hanzo-gateway-lb \
  --region nyc1 \
  --forwarding-rules "entry_protocol:http,entry_port:80,target_protocol:http,target_port:9550" \
  --droplet-ids $(doctl compute droplet list --format ID --no-header | grep hanzo-gateway)
```

## SSL/TLS Setup

### Option 1: DigitalOcean Load Balancer (Recommended)
```bash
# Add SSL certificate to load balancer
doctl compute load-balancer add-forwarding-rules hanzo-gateway-lb \
  --forwarding-rules "entry_protocol:https,entry_port:443,target_protocol:http,target_port:9550,certificate_id:YOUR_CERT_ID"
```

### Option 2: Nginx Reverse Proxy
```bash
# SSH into droplet
make ssh-do

# Install Certbot
apt update && apt install -y certbot nginx

# Get SSL certificate
certbot certonly --standalone -d gateway.hanzo.ai

# Configure Nginx
cat > /etc/nginx/sites-available/gateway << 'EOF'
server {
    listen 443 ssl;
    server_name gateway.hanzo.ai;

    ssl_certificate /etc/letsencrypt/live/gateway.hanzo.ai/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gateway.hanzo.ai/privkey.pem;

    location / {
        proxy_pass http://localhost:9550;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

server {
    listen 80;
    server_name gateway.hanzo.ai;
    return 301 https://$server_name$request_uri;
}
EOF

# Enable site
ln -s /etc/nginx/sites-available/gateway /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

## Domain Setup

### 1. Add DNS Records
```bash
# Point your domain to droplet IP
gateway.hanzo.ai → $(make -s do-ip)  # A record
```

### 2. Update Firewall
```bash
# Allow HTTP/HTTPS
doctl compute firewall create \
  --name hanzo-gateway-fw \
  --inbound-rules "protocol:tcp,ports:80,sources:addresses:0.0.0.0/0,sources:addresses:::/0 protocol:tcp,ports:443,sources:addresses:0.0.0.0/0,sources:addresses:::/0 protocol:tcp,ports:22,sources:addresses:0.0.0.0/0" \
  --droplet-ids $(doctl compute droplet list --format ID --no-header | grep hanzo-gateway)
```

## Troubleshooting

### Gateway Not Responding
```bash
# Check if container is running
make status-do

# Restart container
ssh root@$(make -s do-ip) 'docker restart hanzo-gateway'

# View recent logs
make logs-do
```

### Out of Memory
```bash
# Check memory usage
make ssh-do
free -h

# Resize droplet (requires restart)
doctl compute droplet-action resize hanzo-gateway --size s-2vcpu-2gb
```

### Deployment Failed
```bash
# Check SSH access
ssh root@$(make -s do-ip)

# Check Docker
ssh root@$(make -s do-ip) 'docker ps'

# Manual deployment
make ssh-do
docker pull hanzoai/gateway:latest
docker stop hanzo-gateway && docker rm hanzo-gateway
docker run -d --name hanzo-gateway -p 80:9550 -p 9550:9550 hanzoai/gateway:latest
```

### Cannot Connect to Droplet
```bash
# Check droplet status
doctl compute droplet list

# Check firewall rules
doctl compute firewall list

# Reboot droplet
doctl compute droplet-action reboot hanzo-gateway
```

## Cost Optimization

### Basic Setup ($6/month)
```bash
DO_SIZE := s-1vcpu-1gb      # 1 CPU, 1GB RAM
# Perfect for: Testing, low traffic, personal use
```

### Production Setup ($12-18/month)
```bash
DO_SIZE := s-2vcpu-2gb      # 2 CPU, 2GB RAM
# Perfect for: Production, moderate traffic, 100+ users
```

### High Traffic ($40-80/month)
```bash
DO_SIZE := s-4vcpu-8gb      # 4 CPU, 8GB RAM
# Perfect for: High traffic, 1000+ concurrent users
```

### Cost Breakdown
- Droplet: $6-80/month (based on size)
- Load Balancer: $12/month (optional)
- Snapshots: $0.05/GB/month (optional)
- Bandwidth: Free (1TB included)

## Backup & Restore

### Create Snapshot
```bash
# Create snapshot
doctl compute droplet-action snapshot hanzo-gateway \
  --snapshot-name "hanzo-gateway-$(date +%Y%m%d)"

# List snapshots
doctl compute snapshot list
```

### Restore from Snapshot
```bash
# Create new droplet from snapshot
doctl compute droplet create hanzo-gateway-restored \
  --size s-1vcpu-1gb \
  --image SNAPSHOT_ID \
  --region nyc1
```

## Maintenance

### Update Docker Image
```bash
# Pull latest image
make update-do

# Or manually:
ssh root@$(make -s do-ip) 'docker pull hanzoai/gateway:latest && docker restart hanzo-gateway'
```

### System Updates
```bash
# SSH into droplet
make ssh-do

# Update packages
apt update && apt upgrade -y

# Reboot if needed
reboot
```

### Clean Up Old Images
```bash
make ssh-do
docker system prune -a -f
```

## Cleanup

### Stop Gateway (Keep Droplet)
```bash
ssh root@$(make -s do-ip) 'docker stop hanzo-gateway'
```

### Destroy Everything
```bash
# Destroy droplet
make destroy-do

# Remove from DNS
# Remove from load balancer (if used)
```

## Production Checklist

- [ ] Droplet created and accessible
- [ ] Gateway deployed and responding
- [ ] Health check passing
- [ ] Domain configured (if applicable)
- [ ] SSL/TLS enabled (if applicable)
- [ ] Firewall rules configured
- [ ] Monitoring setup (logs, metrics)
- [ ] Backup strategy (snapshots)
- [ ] Documentation updated

## Next Steps

1. **Add Rate Limiting**: Integrate with hanzo-id for usage tracking
2. **Setup Monitoring**: Prometheus + Grafana
3. **Configure Alerts**: Uptime monitoring, error alerts
4. **Scale Horizontally**: Add load balancer + multiple droplets
5. **CDN Integration**: Cloudflare for DDoS protection

## Support

- **Issues**: https://github.com/hanzoai/gateway/issues
- **Docs**: https://docs.hanzo.ai/gateway
- **Discord**: https://discord.gg/hanzo

---

**Quick Reference**:
```bash
make deploy-full   # Full setup (one command)
make deploy-do     # Deploy to existing droplet
make status-do     # Check status
make logs-do       # View logs
make ssh-do        # SSH access
make destroy-do    # Clean up
```
