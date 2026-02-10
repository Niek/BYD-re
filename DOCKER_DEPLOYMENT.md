# Docker Deployment Guide

This guide explains how to deploy the BYD client using Docker and GitHub Container Registry.

## Prerequisites

- Docker installed locally (for building)
- GitHub account with a repository fork/clone
- BYD account credentials (email and password)

## Local Development

### Quick Start with Docker Compose

1. **Create your `.env` file** (copy from `.env.example`):
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

2. **Start the container**:
   ```bash
   docker-compose up
   ```

3. **Access the dashboard**:
   - Status page: http://localhost:3000
   - Health check: http://localhost:3000/health
   - API status: http://localhost:3000/api/status

### Building Locally

```bash
docker build -t byd-client:latest .
```

### Running Locally

```bash
docker run -it \
  --env-file .env \
  -p 3000:3000 \
  byd-client:latest
```

## GitHub Container Registry Deployment

### Setup (One-time)

1. **Create a personal access token** (GitHub Settings → Developer settings → Personal access tokens):
   - Select scopes: `write:packages`, `read:packages`, `delete:packages`

2. **Authenticate Docker**:
   ```bash
   echo YOUR_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin
   ```

### Building and Pushing

Replace `YOUR_USERNAME` with your GitHub username:

```bash
docker build -t ghcr.io/YOUR_USERNAME/byd-client:latest .
docker push ghcr.io/YOUR_USERNAME/byd-client:latest
```

Or use Git tags for versioning:

```bash
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0

# GitHub Actions will automatically build and push with tags:
# - ghcr.io/YOUR_USERNAME/byd-client:v1.0.0
# - ghcr.io/YOUR_USERNAME/byd-client:latest
```

### Automated Builds with GitHub Actions

The repository includes `.github/workflows/docker-build.yml` which automatically:
- Builds on pushes to `main` branch
- Builds on semantic version tags (`v*`)
- Builds and tests on pull requests
- Pushes to GHCR automatically for main branch and tags
- Caches build layers for faster builds

### Running from GHCR

```bash
docker run -it \
  --env BYD_USERNAME=your@email.com \
  --env BYD_PASSWORD=your-password \
  --env REFRESH_INTERVAL_MINUTES=15 \
  -p 3000:3000 \
  ghcr.io/YOUR_USERNAME/byd-client:latest
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BYD_USERNAME` | (required) | BYD account email |
| `BYD_PASSWORD` | (required) | BYD account password |
| `BYD_COUNTRY_CODE` | `NL` | Country code for API |
| `BYD_LANGUAGE` | `en` | Language preference |
| `BYD_VIN` | (optional) | Vehicle VIN for filtering |
| `BYD_IMEI_MD5` | `00000...` | Device IMEI hash |
| `PORT` | `3000` | HTTP server port |
| `REFRESH_INTERVAL_MINUTES` | `15` | Data refresh interval in minutes |
| `NODE_ENV` | `production` | Node.js environment |

### Customizing Refresh Interval

To change data refresh interval:

```bash
# Via environment variable
docker run -e REFRESH_INTERVAL_MINUTES=5 byd-client

# Via docker-compose
# Edit docker-compose.yml and change:
# REFRESH_INTERVAL_MINUTES=5
docker-compose up
```

## Server Endpoints

- **GET `/`** - Display vehicle dashboard (HTML)
- **GET `/status`** - Same as `/`
- **GET `/health`** - JSON health/status information
- **GET `/api/status`** - Same as `/health`

### Health Check Response

```json
{
  "ok": true,
  "uptime": 3600.5,
  "lastUpdate": "2024-02-10T12:30:45.123Z",
  "refreshIntervalMinutes": 15,
  "isRefreshing": false
}
```

## Troubleshooting

### Container won't start

Check logs:
```bash
docker-compose logs -f byd-client
```

### Authentication errors

Verify `.env` file has correct credentials:
```bash
grep BYD_USERNAME .env
grep BYD_PASSWORD .env
```

### Data not updating

Check the refresh interval configuration:
```bash
curl http://localhost:3000/health | jq .refreshIntervalMinutes
```

Monitor logs for errors:
```bash
docker-compose logs -f --tail=50
```

### Port already in use

Change the port in `docker-compose.yml`:
```yaml
ports:
  - "3001:3000"  # Use 3001 instead
```

## Security Considerations

⚠️ **Important**: Never commit `.env` file with real credentials to Git.

- `.env` is automatically ignored by `.gitignore`
- Use `.env.example` as a template for others
- Keep `.env` local and never share
- Use GitHub Secrets for CI/CD deployments

## Production Deployment

For production deployment options:

### Docker Swarm
```bash
docker service create \
  --name byd-client \
  --env BYD_USERNAME=user@example.com \
  --env BYD_PASSWORD=password \
  -p 3000:3000 \
  ghcr.io/YOUR_USERNAME/byd-client:latest
```

### Kubernetes
Create a Secret for credentials:
```bash
kubectl create secret generic byd-credentials \
  --from-literal=BYD_USERNAME=user@example.com \
  --from-literal=BYD_PASSWORD=password
```

### systemd (standalone server)
Create a systemd service file that starts Docker container on boot.

## Support

For issues with:
- **BYD API**: Check `README.md` documentation
- **Docker**: See Docker official documentation
- **This setup**: File an issue on GitHub

## License

Follow the main repository license terms.
