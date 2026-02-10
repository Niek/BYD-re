#!/bin/bash
# Build and push Docker image to GitHub Container Registry
# Usage: ./scripts/docker-push.sh [TAG]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
GITHUB_USERNAME="${GITHUB_ACTOR:-$(git config user.name | tr ' ' '-' | tr '[:upper:]' '[:lower:]')}"
REGISTRY="ghcr.io"
REPO_NAME="byd-client"
IMAGE_NAME="$REGISTRY/$GITHUB_USERNAME/$REPO_NAME"
TAG="${1:-latest}"

# Validate inputs
if [ -z "$GITHUB_USERNAME" ]; then
  echo -e "${RED}Error: Could not determine GitHub username${NC}"
  echo "Please set GITHUB_ACTOR environment variable or configure git user.name"
  exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
  echo -e "${RED}Error: Docker is not installed${NC}"
  exit 1
fi

# Check if Dockerfile exists
if [ ! -f "Dockerfile" ]; then
  echo -e "${RED}Error: Dockerfile not found in current directory${NC}"
  exit 1
fi

echo -e "${YELLOW}Building Docker image...${NC}"
echo "Image: $IMAGE_NAME:$TAG"

# Build the image
if docker build -t "$IMAGE_NAME:$TAG" .; then
  echo -e "${GREEN}✓ Build successful${NC}"
else
  echo -e "${RED}✗ Build failed${NC}"
  exit 1
fi

# Check if authenticated to registry
echo ""
echo -e "${YELLOW}Checking Docker authentication...${NC}"
if docker image inspect "$IMAGE_NAME:$TAG" > /dev/null 2>&1; then
  echo -e "${GREEN}✓ Image built successfully${NC}"
else
  echo -e "${RED}✗ Failed to verify image${NC}"
  exit 1
fi

# Prompt for push confirmation
echo ""
read -p "Push image to $REGISTRY? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}Push cancelled${NC}"
  exit 0
fi

# Push the image
echo -e "${YELLOW}Pushing image to registry...${NC}"
if docker push "$IMAGE_NAME:$TAG"; then
  echo -e "${GREEN}✓ Push successful${NC}"
  echo ""
  echo -e "${GREEN}Image available at:${NC}"
  echo "  $IMAGE_NAME:$TAG"
  echo ""
  echo -e "${YELLOW}To run:${NC}"
  echo "  docker run -it \\"
  echo "    --env BYD_USERNAME=user@example.com \\"
  echo "    --env BYD_PASSWORD=password \\"
  echo "    -p 3000:3000 \\"
  echo "    $IMAGE_NAME:$TAG"
else
  echo -e "${RED}✗ Push failed${NC}"
  echo "Make sure you're authenticated to $REGISTRY"
  echo "  docker login $REGISTRY"
  exit 1
fi
