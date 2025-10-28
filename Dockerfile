# Hanzo Gateway - Simple Node.js Proxy
FROM node:20-slim

# Install dependencies
WORKDIR /app
COPY gateway/package*.json ./
RUN npm ci --only=production

# Copy gateway code
COPY gateway/test-server.js ./server.js
COPY gateway/.env.example ./.env.example

# Use existing node user (UID 1000)
RUN chown -R node:node /app
USER node

# Gateway runs on port 3030
EXPOSE 3030

# Environment variables
ENV NODE_ENV=production \
    PORT=3030 \
    HOST=0.0.0.0 \
    GATEWAY_IDENTITY=did:hanzo:gateway

CMD ["node", "server.js"]
