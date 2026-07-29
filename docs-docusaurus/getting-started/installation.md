---
id: installation
title: Installation
sidebar_label: Installation
---

# Installation Guide

This guide covers all methods to install and run Shadow SSO.

## Prerequisites

Before installing Shadow SSO, ensure you have:

- **Go 1.25+** (for building from source)
- **MongoDB 5.0+** (for user/client storage)
- **Docker** (optional, for containerized deployment)
- **Helm 3.x** (optional, for Kubernetes deployment)

## Installation Methods

### Method 1: Go Install (Recommended for Development)

Install the server and CLI tools directly using `go install`:

```bash
# Install the SSO server
go install github.com/pilab-dev/shadow-sso/apps/ssso@latest

# Install the CLI tool
go install github.com/pilab-dev/shadow-sso/apps/ssoctl@latest
```

The binaries will be installed to `$GOPATH/bin/`. Ensure this directory is in your `PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Method 2: Build from Source

Clone the repository and build from source:

```bash
# Clone the repository
git clone https://github.com/pilab-dev/shadow-sso.git
cd shadow-sso

# Build the server
go build -o ssso ./apps/ssso/

# Build the CLI
go build -o ssoctl ./apps/ssoctl/

# (Optional) Build the DTS service
go build -o ssso-dts ./apps/ssso-dts/cmd/server/
```

### Method 3: Docker

Pull the official Docker image:

```bash
docker pull ghcr.io/pilab-dev/shadow-sso-backend:v1
```

Or build locally:

```bash
docker build -t shadow-sso:local .
```

### Method 4: Kubernetes (Helm)

Add the Helm chart (when published to a registry):

```bash
helm repo add shadow-sso https://charts.pilab.dev
helm install ssso-backend shadow-sso/ssso-backend
```

Or install from local chart:

```bash
helm install ssso-backend ./helm/ssso-backend
```

## Verify Installation

After installation, verify the binaries are working:

```bash
# Check server version
ssso --version

# Check CLI version
ssoctl --version

# View available commands
ssoctl --help
```

## Next Steps

1. [Quick Start Guide](/getting-started/quickstart) - Run your first SSO server
2. [Configuration](/getting-started/configuration) - Configure your deployment
3. [Deployment Options](/deployment/docker) - Choose your deployment method
