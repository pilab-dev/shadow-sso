# Stage 1: Builder
FROM golang:1.21-alpine AS builder

LABEL maintainer="Shadow SSO Team"
LABEL stage="builder"

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download && go mod verify

# Copy the entire project source code
COPY . .

# Build the server binary
# CGO_ENABLED=0 for a static binary (if possible, depends on dependencies)
# GOOS=linux for Linux target (common for containers)
# -a to force rebuilding of packages that are already up-to-date.
# -installsuffix cgo to prevent conflicts with cgo packages.
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/server cmd/server/main.go

# Stage 2: Final image
FROM alpine:latest
# FROM gcr.io/distroless/static-debian11 AS final # Alternative for a smaller, more secure base

# Add ca-certificates for HTTPS calls if needed by the application
RUN apk --no-cache add ca-certificates

# Set working directory
WORKDIR /app

# Copy the built server binary from the builder stage
COPY --from=builder /app/server /app/server

# Copy example configuration. In a real deployment, this might be mounted as a volume
# or managed by a configuration service.
COPY config.yaml.example /app/config.yaml

# Expose ports. These are documentary and should match the ports your application listens on.
# Default ports from Viper config: HTTP 8080, gRPC 8081
EXPOSE 8080
EXPOSE 8081

# Set environment variables
# GIN_MODE=release is good practice for production to improve performance and reduce logging.
ENV GIN_MODE=release
# Example: If Viper needs to be explicitly told where to find the config inside the container.
# However, the LoadConfig function already searches "." (current working directory), /etc/shadow-sso/, $HOME/.shadow-sso
# So, if config.yaml is in /app/, it should be found. This ENV might be redundant or for override.
# ENV VIPER_CONFIG_PATH=/app/config.yaml

# Command to run the server
# The binary needs to be executable, which `COPY --from=builder` should preserve.
# If not, add: RUN chmod +x /app/server
CMD ["/app/server"]
