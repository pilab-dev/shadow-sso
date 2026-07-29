#!/usr/bin/env bash
# Build and push Docker image to GHCR (amd64)
# Usage: ./scripts/build-and-push.sh [version-tag] [environment]
# Example: ./scripts/build-and-push.sh v1.2.3 production

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Configuration
REGISTRY="ghcr.io"
ORG="pilab-dev"
IMAGE_NAME="shadow-sso-backend"
DOCKERFILE="Dockerfile"
PLATFORM="linux/amd64"

# Parse arguments
VERSION_TAG="${1:-$(git rev-parse --short HEAD)}"
ENVIRONMENT="${2:-dev}"

FULL_IMAGE="${REGISTRY}/${ORG}/${IMAGE_NAME}:${VERSION_TAG}"
LATEST_IMAGE="${REGISTRY}/${ORG}/${IMAGE_NAME}:latest"

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker buildx version &> /dev/null; then
        log_error "Docker Buildx is not available"
        exit 1
    fi
    
    # Check if logged into GHCR
    if ! docker info 2>/dev/null | grep -q "ghcr.io"; then
        log_warn "Not logged into GHCR. Run: docker login ghcr.io -u USERNAME -p TOKEN"
    fi
    
    log_success "Prerequisites check passed"
}

build_and_push() {
    log_info "Building image for ${PLATFORM}..."
    log_info "Image: ${FULL_IMAGE}"
    
    # Create/use buildx builder for multi-platform
    if ! docker buildx inspect multiarch &> /dev/null; then
        log_info "Creating buildx builder 'multiarch'..."
        docker buildx create --name multiarch --driver docker-container --use
    else
        docker buildx use multiarch
    fi
    
    # Build and push
    docker buildx build \
        --platform "${PLATFORM}" \
        --file "${DOCKERFILE}" \
        --tag "${FULL_IMAGE}" \
        --tag "${LATEST_IMAGE}" \
        --push \
        .
    
    log_success "Image built and pushed successfully"
    log_info "Tags pushed:"
    log_info "  - ${FULL_IMAGE}"
    log_info "  - ${LATEST_IMAGE}"
}

main() {
    echo "============================================"
    echo "  Shadow SSO Build & Push Script"
    echo "============================================"
    echo "Version: ${VERSION_TAG}"
    echo "Environment: ${ENVIRONMENT}"
    echo "Platform: ${PLATFORM}"
    echo "Image: ${FULL_IMAGE}"
    echo "============================================"
    echo
    
    check_prerequisites
    build_and_push
    
    echo
    echo "============================================"
    log_success "Build and push completed successfully!"
    echo "============================================"
    echo
    echo "To deploy to Kubernetes:"
    echo "  ./scripts/deploy.sh ${VERSION_TAG} ${ENVIRONMENT}"
    echo
    echo "Or update Helm values manually:"
    echo "  image:"
    echo "    repository: ${REGISTRY}/${ORG}/${IMAGE_NAME}"
    echo "    tag: \"${VERSION_TAG}\""
}

main "$@"