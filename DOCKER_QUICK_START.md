# 🐳 Docker Setup Complete

Your BYD client is now fully containerized and ready for GitHub Container Registry deployment.

## 📦 What's New

### Core Files (4 files)
```
✅ Dockerfile              - Container image definition (Node.js 20 Alpine)
✅ docker-compose.yml      - Full service orchestration
✅ .dockerignore           - Build context optimization
✅ server.js               - HTTP server wrapper for client.js
```

### Configuration (2 files)
```
✅ .env.example            - Standard environment template
✅ .env.docker             - Docker-specific configuration template
```

### Documentation (5 files)
```
✅ DOCKER_COMPLETE.md      - This setup completion summary
✅ DOCKER_DEPLOYMENT.md    - Full production deployment guide (5000+ words)
✅ DOCKER_SETUP.md         - Technical setup details
✅ QUICK_REFERENCE.md      - Docker command cheat sheet
✅ README.md               - Updated with Docker section
```

### CI/CD (1 file)
```
✅ .github/workflows/docker-build.yml  - GitHub Actions automation
```

### Utilities (2 files)
```
✅ scripts/docker-push.sh   - Interactive build/push helper
✅ Makefile                 - Convenient make commands
```

**Total: 15 new files created**

---

## 🚀 Quick Start (Pick One)

### Option 1: docker-compose (Recommended)
```bash
cp .env.example .env
# Edit .env with your BYD credentials
docker-compose up
# Visit: http://localhost:3000
```

### Option 2: Make commands
```bash
cp .env.example .env
# Edit .env with your BYD credentials
make up
# Visit: http://localhost:3000
```

### Option 3: Manual Docker
```bash
docker build -t byd-client:latest .
docker run -it --env-file .env -p 3000:3000 byd-client:latest
# Visit: http://localhost:3000
```

---

## 🌐 Server Features

### HTTP Endpoints
- **GET `/`** → Vehicle dashboard (HTML)
- **GET `/health`** → Server health (JSON)
- **GET `/api/status`** → Server status (JSON)

### Key Configuration
| Variable | Default | Usage |
|----------|---------|-------|
| `PORT` | 3000 | HTTP server port |
| `REFRESH_INTERVAL_MINUTES` | 15 | Auto-refresh data every N minutes |
| `BYD_USERNAME` | (required) | Your BYD email |
| `BYD_PASSWORD` | (required) | Your BYD password |

### Example Health Check
```bash
curl http://localhost:3000/health | jq
```

Output:
```json
{
  "ok": true,
  "uptime": 3600.5,
  "lastUpdate": "2024-02-10T12:30:45.123Z",
  "refreshIntervalMinutes": 15,
  "isRefreshing": false
}
```

---

## 📤 GitHub Container Registry (GHCR)

### Automatic (GitHub Actions)
1. Update code → Push to `main` branch
2. CI/CD automatically builds and pushes to GHCR
3. Image available at: `ghcr.io/YOUR_USERNAME/byd-client:latest`

### Manual Push
```bash
# Using helper script
bash scripts/docker-push.sh latest

# Or manually
docker build -t ghcr.io/YOUR_USERNAME/byd-client:latest .
docker push ghcr.io/YOUR_USERNAME/byd-client:latest
```

### Run from GHCR
```bash
docker run -it \
  -e BYD_USERNAME=your@email.com \
  -e BYD_PASSWORD=your-password \
  -p 3000:3000 \
  ghcr.io/YOUR_USERNAME/byd-client:latest
```

---

## 🛠️ Available Commands

### Using docker-compose
```bash
docker-compose up              # Start
docker-compose down            # Stop
docker-compose logs -f         # View logs
docker-compose restart         # Restart
```

### Using make (Makefile)
```bash
make up                         # Start containers
make down                       # Stop containers
make logs                       # View logs
make logs-follow               # Follow logs
make test                      # Health check
make build                     # Build image
make push                      # Push to GHCR
make clean                     # Clean up
make help                      # Show all commands
```

### Using plain Docker
```bash
docker build -t byd-client:latest .
docker run -it --env-file .env -p 3000:3000 byd-client:latest
docker logs <container-id>
docker exec -it <container-id> /bin/sh
```

---

## 📚 Documentation

| Document | Purpose | Audience |
|----------|---------|----------|
| **QUICK_REFERENCE.md** | Common commands cheat sheet | Quick lookup |
| **DOCKER_DEPLOYMENT.md** | Complete deployment guide | Detailed reference |
| **DOCKER_SETUP.md** | Technical architecture details | Developers |
| **DOCKER_COMPLETE.md** | Setup completion summary | Overview |
| **.env.example** | Environment variables template | Configuration |
| **Makefile** | Convenient commands | Automation |

---

## 🔒 Security Features

✅ Non-root container user (nodejs:1001)
✅ `.env` excluded from git
✅ Multi-stage Dockerfile optimization
✅ Health checks for monitoring
✅ Proper signal handling (SIGTERM/SIGINT)
✅ No hardcoded secrets

---

## 🎯 How It Works

```
┌─────────────────────────────────────────────────┐
│          Docker Container (Node.js)            │
│  ┌──────────────────────────────────────────┐  │
│  │  server.js (HTTP Server)                │  │
│  │  • Listens on port 3000                 │  │
│  │  • Serves status.html dashboard         │  │
│  │  • Health check endpoints               │  │
│  └──────────────────────────────────────────┘  │
│                      ↓                          │
│  ┌──────────────────────────────────────────┐  │
│  │  client.js (BYD API Client)             │  │
│  │  • Fetches vehicle data                 │  │
│  │  • Generates status.html                │  │
│  │  • Runs on configurable interval        │  │
│  └──────────────────────────────────────────┘  │
│                      ↓                          │
│  ┌──────────────────────────────────────────┐  │
│  │  Crypto Stack (bangcle.js)              │  │
│  │  • Encrypts/decrypts payloads           │  │
│  │  • Handles authentication               │  │
│  └──────────────────────────────────────────┘  │
│                      ↓                          │
│          BYD API: dilinkappoversea-eu.byd.auto │
└─────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow

1. **Server starts** → Initial `client.js` run
2. **Dashboard generated** → `status.html` created
3. **Serves on port 3000** → Users access dashboard
4. **On interval** (every N minutes):
   - Run `client.js`
   - Fetch vehicle data from BYD API
   - Decrypt responses
   - Generate new `status.html`
   - Serve updated dashboard

---

## ⚙️ Environment Configuration

### Required
```env
BYD_USERNAME=your@email.com
BYD_PASSWORD=your-password
```

### Optional (Common)
```env
BYD_COUNTRY_CODE=NL
BYD_LANGUAGE=en
BYD_VIN=optional-vehicle-vin
```

### Server
```env
PORT=3000
REFRESH_INTERVAL_MINUTES=15
```

See `.env.example` for all available options.

---

## 🧪 Testing

### Health Check
```bash
curl http://localhost:3000/health | jq
```

### Dashboard Access
```bash
open http://localhost:3000
# or
curl http://localhost:3000 | head -20
```

### Container Status
```bash
docker-compose ps
docker-compose logs -f --tail=50
```

---

## 🐛 Troubleshooting

### Container won't start?
```bash
docker-compose logs -f
```

### Port 3000 in use?
Edit `docker-compose.yml`:
```yaml
ports:
  - "3001:3000"  # Use port 3001 instead
```

### Authentication failed?
Check `.env`:
```bash
grep BYD_ .env
```

### Data not updating?
```bash
curl http://localhost:3000/health | jq .lastUpdate
docker-compose logs | grep "refresh\|error"
```

---

## 📋 Verification Checklist

- ✅ `server.js` created (173 lines)
- ✅ `Dockerfile` created (51 lines)
- ✅ `docker-compose.yml` created (28 lines)
- ✅ `DOCKER_DEPLOYMENT.md` created (comprehensive guide)
- ✅ GitHub Actions workflow created (`.github/workflows/docker-build.yml`)
- ✅ Helper script created (`scripts/docker-push.sh`)
- ✅ Makefile created with convenient commands
- ✅ Environment templates created (`.env.example`, `.env.docker`)
- ✅ Quick reference guide created (`QUICK_REFERENCE.md`)
- ✅ README updated with Docker section
- ✅ `.gitignore` updated for Docker files

---

## 🎓 Learning Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Guide](https://docs.docker.com/compose/)
- [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

---

## 📞 Quick Links

- **Start**: `docker-compose up`
- **Dashboard**: http://localhost:3000
- **Health**: http://localhost:3000/health
- **Logs**: `docker-compose logs -f`
- **Stop**: `docker-compose down`

---

## ✨ What's Next?

1. **Test locally**: `docker-compose up`
2. **Verify dashboard**: Visit http://localhost:3000
3. **Check health**: `curl http://localhost:3000/health`
4. **Set up GHCR**: Follow [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)
5. **Configure CI/CD**: Push to repository to trigger GitHub Actions
6. **Deploy**: Use image from GHCR in production

---

**Everything is ready to use!**

Start with: `docker-compose up` → Visit http://localhost:3000
