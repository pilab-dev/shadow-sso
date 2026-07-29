#!/usr/bin/env bash
# Deploy new image version to Kubernetes using Helm
# Usage: ./scripts/deploy.sh [version-tag] [environment] [namespace]
# Example: ./scripts/deploy.sh v1.2.3 production shadow-sso

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
HELM_CHART_PATH="helm/ssso-backend"
HELM_RELEASE_NAME="ssso-backend"
REGISTRY="ghcr.io"
ORG="pilab-dev"
IMAGE_NAME="shadow-sso-backend"

# Parse arguments
VERSION_TAG="${1:-$(git rev-parse --short HEAD)}"
ENVIRONMENT="${2:-dev}"
NAMESPACE="${3:-shadow-sso}"

FULL_IMAGE="${REGISTRY}/${ORG}/${IMAGE_NAME}:${VERSION_TAG}"
VALUES_FILE="${HELM_CHART_PATH}/values-${ENVIRONMENT}.yaml"

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    for cmd in helm kubectl; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "$cmd is not installed or not in PATH"
            exit 1
        fi
    done
    
    # Check if values file exists
    if [[ ! -f "${VALUES_FILE}" ]]; then
        log_warn "Environment values file not found: ${VALUES_FILE}"
        log_info "Using default values.yaml"
        VALUES_FILE="${HELM_CHART_PATH}/values.yaml"
    fi
    
    # Check kubectl context (non-fatal - may not have one configured)
    local current_context
    current_context=$(kubectl config current-context 2>/dev/null || echo "none configured")
    log_info "Kubernetes context: ${current_context}"
    
    log_success "Prerequisites check passed"
}

deploy() {
    log_info "Deploying with Helm..."
    log_info "Release: ${HELM_RELEASE_NAME}"
    log_info "Namespace: ${NAMESPACE}"
    log_info "Chart: ${HELM_CHART_PATH}"
    log_info "Values: ${VALUES_FILE}"
    log_info "Image tag: ${VERSION_TAG}"
    
    helm upgrade --install "${HELM_RELEASE_NAME}" "${HELM_CHART_PATH}" \
        --namespace "${NAMESPACE}" \
        --create-namespace \
        --values "${VALUES_FILE}" \
        --set "image.tag=${VERSION_TAG}" \
        --wait \
        --timeout 5m
    
    log_success "Helm deployment completed"
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    kubectl get pods -l "app.kubernetes.io/instance=${HELM_RELEASE_NAME}" \
        --namespace "${NAMESPACE}" \
        -o wide
    
    log_info "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod \
        -l "app.kubernetes.io/instance=${HELM_RELEASE_NAME}" \
        --namespace "${NAMESPACE}" \
        --timeout=2m
    
    log_success "Deployment verified - all pods ready"
}

main() {
    echo "============================================"
    echo "  Shadow SSO Deploy Script"
    echo "============================================"
    echo "Version: ${VERSION_TAG}"
    echo "Environment: ${ENVIRONMENT}"
    echo "Namespace: ${NAMESPACE}"
    echo "Image: ${FULL_IMAGE}"
    echo "============================================"
    echo
    
    check_prerequisites
    
    deploy
    verify_deployment
    
    echo
    echo "============================================"
    log_success "Deployment completed successfully!"
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

main "$@"