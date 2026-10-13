# syntax=docker/dockerfile:1

FROM node:24.21.0-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Only the static cloudflared binary is taken from this image.
FROM cloudflare/cloudflared:2026.9.3 AS cloudflared

FROM node:24.21.0-alpine
ENV NODE_ENV=production PORT=8080 CONFIG_PATH=/config/proxy.config.json DATA_DIR=/data
WORKDIR /app
COPY --from=cloudflared /usr/local/bin/cloudflared /usr/local/bin/cloudflared
# The bundle has no runtime dependencies, so no node_modules.
COPY --from=build /app/dist ./dist
RUN printf '#!/bin/sh\nexec node /app/dist/cli.mjs "$@"\n' > /usr/local/bin/mcp-proxy \
 && chmod +x /usr/local/bin/mcp-proxy \
 && mkdir -p /data /config && chown node:node /data
USER node
# This node's own upstream login lives here; give each node its own volume.
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
CMD ["node", "dist/server.mjs"]
