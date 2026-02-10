.PHONY: help build up down logs test push clean

help:
	@echo "BYD Client Docker Commands"
	@echo ""
	@echo "Usage: make [command]"
	@echo ""
	@echo "Commands:"
	@echo "  build         Build Docker image"
	@echo "  up            Start containers with docker-compose"
	@echo "  down          Stop containers"
	@echo "  logs          View container logs"
	@echo "  logs-follow   Follow container logs"
	@echo "  test          Quick health check test"
	@echo "  shell         Open shell in running container"
	@echo "  clean         Remove containers and images"
	@echo "  push          Build and push to GHCR (requires auth)"
	@echo "  help          Show this help message"
	@echo ""
	@echo "Environment Variables:"
	@echo "  PORT                      HTTP server port (default: 3000)"
	@echo "  REFRESH_INTERVAL_MINUTES  Data refresh interval (default: 15)"
	@echo ""
	@echo "Examples:"
	@echo "  make up                              # Start local containers"
	@echo "  make logs                            # View logs"
	@echo "  REFRESH_INTERVAL_MINUTES=5 make up # Start with 5-min refresh"
	@echo ""

build:
	@echo "Building Docker image..."
	docker build -t byd-client:latest .
	@echo "✓ Build complete"

up:
	@echo "Starting containers..."
	docker-compose up

down:
	@echo "Stopping containers..."
	docker-compose down
	@echo "✓ Containers stopped"

logs:
	docker-compose logs

logs-follow:
	docker-compose logs -f --tail=50

test:
	@echo "Testing server health..."
	@sleep 2
	@curl -s http://localhost:3000/health | jq . || echo "Server not responding"

shell:
	@CONTAINER=$$(docker-compose ps -q byd-client 2>/dev/null); \
	if [ -z "$$CONTAINER" ]; then \
	  echo "Container not running. Start with: make up"; \
	  exit 1; \
	fi; \
	docker exec -it $$CONTAINER /bin/sh

push:
	@bash scripts/docker-push.sh latest

clean:
	@echo "Cleaning up Docker artifacts..."
	docker-compose down -v
	docker images | grep byd-client | awk '{print $$3}' | xargs -r docker rmi
	@echo "✓ Cleanup complete"

# Development shortcuts
dev-build: down build
dev-up: build up
dev-logs: logs-follow
dev-fresh: clean build up

# Production shortcuts
prod-push: build push

.SILENT: help test
