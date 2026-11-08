#!/usr/bin/env bash
# Build, push, and deploy script for Shadow SSO
# Usage: ./scripts/build-and-deploy.sh [version-tag] [environment]
# Example: ./scripts/build-and-deploy.sh v1.2.3 production
# Defaults: tag = current git short SHA, environment = production, NAMESPACE env = shadow-sso
#
# Production values are maintained in the pistack repository and are
# deliberately not committed here. Set HELM_VALUES_FILE explicitly or keep the
# pistack checkout at ../pistack/shadow-sso/values.yaml.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="ghcr.io"
REPOSITORY="pilab-dev/shadow-sso-backend"
DEFAULT_TAG="$(git rev-parse --short HEAD)"
ENVIRONMENT="${2:-production}"
HELM_CHART_PATH="helm/ssso-backend"
HELM_RELEASE_NAME="ssso-backend"
NAMESPACE="${NAMESPACE:-shadow-sso}"
HELM_VALUES_FILE="${HELM_VALUES_FILE:-}"

# Parse arguments
VERSION_TAG="${1:-${DEFAULT_TAG}}"
FULL_IMAGE="${REGISTRY}/${REPOSITORY}:${VERSION_TAG}"
LATEST_IMAGE="${REGISTRY}/${REPOSITORY}:latest"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    command -v docker >/dev/null 2>&1 || { log_error "docker is required but not installed."; exit 1; }
    command -v helm >/dev/null 2>&1 || { log_error "helm is required but not installed."; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl is required but not installed."; exit 1; }
    
    # Check if logged into GHCR
    if ! grep -q "ghcr.io" ~/.docker/config.json 2>/dev/null; then
        log_warn "Not logged into GHCR. Run: docker login ghcr.io -u USERNAME --password-stdin"
    fi
    
    log_success "Prerequisites check passed"
}

build_image() {
    log_info "Building Docker image for linux/amd64..."
    log_info "Image: ${FULL_IMAGE}"
    
    docker buildx build \
        --platform linux/amd64 \
        --file Dockerfile \
        --tag "${FULL_IMAGE}" \
        --tag "${LATEST_IMAGE}" \
        --push \
        .
    
    log_success "Image built and pushed: ${FULL_IMAGE}"
}

select_values_file() {
    if [[ -n "${HELM_VALUES_FILE:-}" ]]; then
        if [[ ! -f "${HELM_VALUES_FILE}" ]]; then
            log_error "HELM_VALUES_FILE not found: ${HELM_VALUES_FILE}"
            exit 1
        fi
        echo "${HELM_VALUES_FILE}"
        return
    fi

    if [[ "${ENVIRONMENT}" == "production" ]]; then
        local pistack_values="../pistack/shadow-sso/values.yaml"
        if [[ -f "${pistack_values}" ]]; then
            echo "${pistack_values}"
            return
        fi
        log_error "Production values are maintained in the pistack repository."
        log_error "Set HELM_VALUES_FILE to the production values file (e.g. ../pistack/shadow-sso/values.yaml)."
        exit 1
    fi

    local values_file="${HELM_CHART_PATH}/values-${ENVIRONMENT}.yaml"

    if [[ ! -f "${values_file}" ]]; then
        log_warn "Environment values file not found: ${values_file}"
        log_info "Using default values.yaml"
        values_file="${HELM_CHART_PATH}/values.yaml"
    fi

    echo "${values_file}"
}

deploy_with_helm() {
    local values_file="$1"
    
    log_info "Deploying with Helm..."
    log_info "Release: ${HELM_RELEASE_NAME}"
    log_info "Namespace: ${NAMESPACE}"
    log_info "Values: ${values_file}"
    
    helm upgrade --install "${HELM_RELEASE_NAME}" "${HELM_CHART_PATH}" \
        --namespace "${NAMESPACE}" \
        --create-namespace \
        --values "${values_file}" \
        --set "image.tag=${VERSION_TAG}" \
        --atomic \
        --wait \
        --timeout 5m
    
    log_success "Helm deployment completed"
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    kubectl get pods -l "app.kubernetes.io/instance=${HELM_RELEASE_NAME}" \
        --namespace "${NAMESPACE}" \
        -o wide
    
    log_info "Checking pod readiness..."
    kubectl wait --for=condition=ready pod \
        -l "app.kubernetes.io/instance=${HELM_RELEASE_NAME}" \
        --namespace "${NAMESPACE}" \
        --timeout=2m
    
    log_success "Deployment verified - all pods ready"
}

main() {
    echo "============================================"
    echo "  Shadow SSO Build & Deploy Script"
    echo "============================================"
    echo "Version: ${VERSION_TAG}"
    echo "Environment: ${ENVIRONMENT}"
    echo "Image: ${FULL_IMAGE}"
    echo "Namespace: ${NAMESPACE}"
    echo "============================================"
    echo
    
    check_prerequisites
    build_image
    
    local values_file
    values_file=$(select_values_file)
    
    deploy_with_helm "${values_file}"
    verify_deployment
    
    echo
    echo "============================================"
    log_success "Build and deploy completed successfully!"
    echo "============================================"
    echo "Image: ${FULL_IMAGE}"
    echo "Environment: ${ENVIRONMENT}"
    echo "Namespace: ${NAMESPACE}"
    echo
    echo "To check logs:"
    echo "  kubectl logs -l app.kubernetes.io/instance=${HELM_RELEASE_NAME} -n ${NAMESPACE} -f"
    echo
    echo "To check status:"
    echo "  kubectl get pods -l app.kubernetes.io/instance=${HELM_RELEASE_NAME} -n ${NAMESPACE}"
}

# Run main function
main "$@"