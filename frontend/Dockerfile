# =============================================================================
# KAVACH Frontend — Production Multi-Stage Dockerfile
# Stage 1: Build React/Vite bundle with Node.js
# Stage 2: Serve static files with lightweight Nginx web server
# =============================================================================

# --- Stage 1: Build ---
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package descriptors & install dependencies
COPY package*.json ./
RUN npm ci

# Copy frontend source code & build production bundle
COPY . .
RUN npm run build

# --- Stage 2: Production Nginx Server ---
FROM nginx:alpine

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy static dist bundle from stage 1
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
