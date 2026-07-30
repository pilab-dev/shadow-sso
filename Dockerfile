# Stage 1: Build the Go application
FROM golang:1.25-alpine AS builder

# Set necessary environment variables
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Create appuser
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Install UPX for binary compression
RUN apk add --no-cache upx

WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project source code
COPY . .

# Build the server application (ssso)
RUN go build -ldflags="-w -s" -o /ssso ./apps/ssso/

# Build the CLI tool (ssoctl)
RUN go build -ldflags="-w -s" -o /ssoctl ./apps/sssoctl/

# Compress binaries with UPX (best compression, safe for Go binaries)
RUN upx --best --lzma /ssso /ssoctl

# Stage 2: Create the final lightweight image
FROM alpine:3.21

LABEL org.opencontainers.image.authors="Paal Gyula <gyula@pilab.hu>"
LABEL org.opencontainers.image.source="https://github.com/pilab-dev/shadow-sso"
LABEL org.opencontainers.image.description="Shadow Single Sign-On (SSO) backend headless SSO solution"
LABEL org.opencontainers.image.title="Shadow SSO Backend"
LABEL org.opencontainers.image.vendor="Progressive Innovation LAB"

# Import the user and group from the builder stage
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the compiled application binary from the builder stage
COPY --from=builder /ssso /usr/local/bin/ssso

# Copy the CLI tool binary from the builder stage
COPY --from=builder /ssoctl /usr/local/bin/ssoctl

# Copy configuration files or templates if any (assuming config is mounted or handled externally)
# For example, if you have a default config:
# COPY --from=builder /app/sso_config.yaml.example /etc/sso/sso_config.yaml

COPY docker/ /docker/

# Set the user to run the application
USER appuser

# Expose the port the application runs on (default 8080, can be configured)
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 CMD curl -f http://localhost:5000/healthz || exit 1

ENTRYPOINT ["/docker/entrypoint.sh"]
