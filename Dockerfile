FROM node:20-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Copy application files
COPY bangcle.js ./
COPY bangcle_auth_tables.js ./
COPY client.js ./
COPY server.js ./
COPY decompile.js ./

# Try to copy and install optional package files
RUN if [ -f /app/package.json ] || [ -f /app/package-lock.json ]; then \
      echo "package.json found, installing dependencies"; \
    else \
      echo "No package.json, skipping npm install"; \
    fi

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

# Environment variables
ENV NODE_ENV=production \
    PORT=3000 \
    REFRESH_INTERVAL_MINUTES=15

# Expose port
EXPOSE 3000

# Run with dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
