# Hanzo Gateway - Production Node.js Proxy
FROM node:20-slim

# Install dependencies
WORKDIR /app
COPY gateway/package*.json ./
RUN npm install --only=production

# Copy gateway code (production version with rate limiting and embeddings)
COPY gateway/server.js ./server.js

# Use existing node user (UID 1000)
RUN chown -R node:node /app
USER node

# Gateway runs on port 3001
EXPOSE 3001

# Environment variables
ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0 \
    GATEWAY_IDENTITY=did:hanzo:gateway

CMD ["node", "server.js"]
