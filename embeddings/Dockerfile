# Hanzo Embeddings API - Simple Node.js Server
FROM node:20-slim

WORKDIR /app

# Copy code (no dependencies needed)
COPY server.js ./

# Use existing node user
RUN chown -R node:node /app
USER node

# Embeddings runs on port 3002
EXPOSE 3002

ENV NODE_ENV=production \
    PORT=3002 \
    HOST=0.0.0.0

CMD ["node", "server.js"]
