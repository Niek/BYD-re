# Docker Setup Summary

This document summarizes the Docker containerization added to the BYD client project.

## New Files Created

### Core Docker Files
- **`Dockerfile`** - Multi-stage Docker image build configuration
  - Node.js 20 Alpine base
  - Non-root user for security
  - Health checks enabled
  - Minimal final image size

- **`docker-compose.yml`** - Docker Compose orchestration
  - Pre-configured service setup
  - Environment variable mapping
  - Port binding (3000)
  - Health checks
  - Auto-restart policy

- **`.dockerignore`** - Files excluded from Docker build context
  - Reduces build context size
  - Improves build speed

### Server Application
- **`server.js`** - HTTP server wrapping `client.js`
  - Periodic data refresh with configurable interval
  - Serves generated `status.html` dashboard
  - Health check endpoints (`/health`, `/api/status`)
  - Graceful shutdown handling
  - CORS headers for cross-origin access

### Configuration Templates
- **`.env.example`** - Standard environment variables template
  - All available configuration options documented
  - Safe defaults provided

- **`.env.docker`** - Docker-specific environment template
  - Comprehensive comments for each variable
  - Better organized for container deployments

### Documentation
- **`DOCKER_DEPLOYMENT.md`** - Complete deployment guide
  - Local development instructions
  - GitHub Container Registry setup
  - Kubernetes and Docker Swarm examples
  - Troubleshooting guide
  - Security best practices

### CI/CD Integration
- **`.github/workflows/docker-build.yml`** - GitHub Actions workflow
  - Automatic Docker image builds
  - Push to GitHub Container Registry (GHCR)
  - Semantic versioning support
  - Build caching for performance
  - Runs on: main branch pushes, release tags, pull requests

### Helper Scripts
- **`scripts/docker-push.sh`** - Build and push script
  - Interactive Docker build and push utility
  - Automatic GitHub username detection
  - Authentication checking
  - Colored output with status indicators

## Key Features

### Configuration
| Feature | Details |
|---------|---------|
| **Refresh Interval** | Configurable via `REFRESH_INTERVAL_MINUTES` (default: 15 min) |
| **HTTP Server** | Simple Node.js server on port 3000 |
| **Dashboard** | Auto-generated `status.html` with vehicle data |
| **Health Checks** | Built-in endpoints: `/health`, `/api/status` |

### Docker Image
- **Base**: Node.js 20 Alpine (minimal, secure)
- **Size**: ~200-300 MB (optimized with multi-stage build)
- **User**: Non-root `nodejs` user (UID 1001)
- **Signal Handling**: dumb-init for proper container lifecycle

### Deployment Options
1. **Local Development**: `docker-compose up`
2. **Standalone Docker**: `docker run` with environment variables
3. **GitHub Container Registry**: Automated builds and pushes
4. **Kubernetes**: Example manifests in DOCKER_DEPLOYMENT.md
5. **Docker Swarm**: Service creation examples provided

## Environment Variables

### Required
- `BYD_USERNAME` - BYD account email
- `BYD_PASSWORD` - BYD account password

### Server Configuration
- `PORT` - HTTP server port (default: 3000)
- `REFRESH_INTERVAL_MINUTES` - Data refresh interval (default: 15)

### Optional (Device/Regional)
- `BYD_COUNTRY_CODE` - Regional setting (default: NL)
- `BYD_LANGUAGE` - Language preference (default: en)
- `BYD_VIN` - Filter by vehicle VIN
- `BYD_IMEI_MD5` - Device identifier
- Plus many other device/app version parameters (see `.env.example`)

## Quick Start Examples

### Local Development
```bash
cp .env.example .env
# Edit .env with credentials
docker-compose up
# Access: http://localhost:3000
```

### Build and Run Locally
```bash
docker build -t byd-client:latest .
docker run -it --env-file .env -p 3000:3000 byd-client:latest
```

### Push to GitHub Container Registry
```bash
bash scripts/docker-push.sh latest
# Or manually:
docker build -t ghcr.io/YOUR_USERNAME/byd-client:latest .
docker push ghcr.io/YOUR_USERNAME/byd-client:latest
```

### Run from GHCR
```bash
docker run -it \
  --env BYD_USERNAME=your@email.com \
  --env BYD_PASSWORD=password \
  -p 3000:3000 \
  ghcr.io/YOUR_USERNAME/byd-client:latest
```

## Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Vehicle dashboard (HTML) |
| `/status` | GET | Same as `/` |
| `/health` | GET | Health status (JSON) |
| `/api/status` | GET | Same as `/health` |

### Health Response
```json
{
  "ok": true,
  "uptime": 3600.5,
  "lastUpdate": "2024-02-10T12:30:45.123Z",
  "refreshIntervalMinutes": 15,
  "isRefreshing": false
}
```

## Security Notes

- ✅ `.env` excluded from git (via `.gitignore`)
- ✅ Non-root container user
- ✅ Multi-stage build minimizes image size
- ✅ Health checks for monitoring
- ⚠️ Never commit `.env` with real credentials
- ⚠️ Use GitHub Secrets for CI/CD deployments
- ⚠️ Review hardcoded cryptographic keys in source (see security review)

## Troubleshooting

### Container won't start
```bash
docker-compose logs -f
```

### Port 3000 already in use
Edit `docker-compose.yml`: change `ports: ["3000:3000"]` to `["3001:3000"]`

### Authentication errors
Verify `.env` has correct BYD credentials:
```bash
grep -E 'BYD_USERNAME|BYD_PASSWORD' .env
```

### Data not updating
Check refresh interval:
```bash
curl http://localhost:3000/health | jq .refreshIntervalMinutes
```

## File Structure

```
BYD-re/
├── Dockerfile                    # Container image definition
├── docker-compose.yml           # Compose orchestration
├── .dockerignore                # Build context exclusions
├── server.js                    # HTTP server wrapper
├── DOCKER_DEPLOYMENT.md         # Full deployment guide
├── .env.example                 # Template: standard setup
├── .env.docker                  # Template: Docker-specific
├── .github/
│   └── workflows/
│       └── docker-build.yml     # GitHub Actions CI/CD
└── scripts/
    └── docker-push.sh           # Build/push helper script
```

## Next Steps

1. **Local Testing**: Follow "Quick Start" example above
2. **GitHub Setup**: Configure repository secrets for CD/CI
3. **GHCR Deployment**: Push image and document in wiki
4. **Production**: Review DOCKER_DEPLOYMENT.md for production options

See [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) for detailed instructions.
