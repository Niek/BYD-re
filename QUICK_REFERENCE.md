# Quick Reference: Docker Commands

## Setup

```bash
# Copy environment template
cp .env.example .env

# Edit with your credentials
nano .env  # or your preferred editor
```

## Local Development

```bash
# Start with docker-compose
docker-compose up

# Stop
docker-compose down

# View logs
docker-compose logs -f

# Restart
docker-compose restart
```

## Manual Docker Commands

```bash
# Build image
docker build -t byd-client:latest .

# Run container
docker run -it \
  --env-file .env \
  -p 3000:3000 \
  byd-client:latest

# Run with specific environment variables
docker run -it \
  -e BYD_USERNAME=user@example.com \
  -e BYD_PASSWORD=password \
  -e REFRESH_INTERVAL_MINUTES=10 \
  -p 3000:3000 \
  byd-client:latest

# Stop container
docker stop <container-id>

# View logs
docker logs -f <container-id>

# List images
docker images | grep byd

# Remove image
docker rmi byd-client:latest
```

## GitHub Container Registry (GHCR)

```bash
# Authenticate (one-time)
echo $YOUR_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Using helper script
bash scripts/docker-push.sh latest

# Manual build and push
docker build -t ghcr.io/YOUR_USERNAME/byd-client:latest .
docker push ghcr.io/YOUR_USERNAME/byd-client:latest

# Run from GHCR
docker run -it \
  -e BYD_USERNAME=user@example.com \
  -e BYD_PASSWORD=password \
  -p 3000:3000 \
  ghcr.io/YOUR_USERNAME/byd-client:latest
```

## Monitoring

```bash
# Health check
curl http://localhost:3000/health

# Pretty-print health status
curl http://localhost:3000/health | jq

# View dashboard
open http://localhost:3000

# Check uptime and last update
curl http://localhost:3000/api/status | jq '.uptime, .lastUpdate'

# Monitor logs in real-time
docker-compose logs -f --tail=50
```

## Configuration

```bash
# Change refresh interval to 5 minutes
docker run -it \
  --env-file .env \
  -e REFRESH_INTERVAL_MINUTES=5 \
  -p 3000:3000 \
  byd-client:latest

# Use different port
docker run -it \
  --env-file .env \
  -p 3001:3000 \
  byd-client:latest
```

## Troubleshooting

```bash
# Check if container is running
docker ps | grep byd

# View full container logs
docker-compose logs

# Inspect running container
docker inspect <container-id>

# Execute command in container
docker exec -it <container-id> /bin/sh

# Check image layers
docker history byd-client:latest

# Validate Dockerfile
docker build --no-cache -t byd-client:test . 2>&1 | head -20

# Test health endpoint
docker run --rm -p 3000:3000 byd-client:latest &
sleep 2
curl -s http://localhost:3000/health | jq
```

## Cleanup

```bash
# Stop all containers
docker-compose down

# Remove all stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove all BYD-related images
docker images | grep byd | awk '{print $3}' | xargs docker rmi

# Full cleanup (⚠️ careful!)
docker system prune -a
```

## Useful Environment Variables

```bash
# Standard variables
PORT=3000
REFRESH_INTERVAL_MINUTES=15
NODE_ENV=production

# BYD credentials
BYD_USERNAME=your@email.com
BYD_PASSWORD=your-password

# Regional/Device settings
BYD_COUNTRY_CODE=NL
BYD_LANGUAGE=en
BYD_VIN=vehicle-vin-if-needed
```

## Common Issues

| Issue | Solution |
|-------|----------|
| Port 3000 in use | Use different port: `-p 3001:3000` |
| Authentication error | Check `.env` has correct credentials |
| Data not updating | Check logs: `docker-compose logs` |
| Container won't start | View logs for errors: `docker logs <id>` |
| Can't push to GHCR | Run: `docker login ghcr.io` |
| Image too large | Use: `docker build --no-cache` |

## Links

- [Full Docker Guide](DOCKER_DEPLOYMENT.md)
- [Docker Setup Details](DOCKER_SETUP.md)
- [Main README](README.md)
- [Environment Variables Example](.env.example)

---

**Quick Start**: `docker-compose up` → Access http://localhost:3000
