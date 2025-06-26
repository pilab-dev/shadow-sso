# Stage 1: Build the Go application for SSSO-Alt
FROM golang:1.21-alpine AS builder # Matching ssso-dts Dockerfile Go version for consistency

# Set necessary environment variables
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Create appuser
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
# These paths are relative to the Docker build context (project root)
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project source code
COPY . .

# Build the ssso-alt server application
# Main package for ssso-alt is apps/ssso-alt/cmd/server/main.go
RUN go build -ldflags="-w -s" -o /ssso-alt-server ./apps/ssso-alt/cmd/server

# Stage 2: Create the final lightweight image for SSSO-Alt
FROM alpine:latest

# Import the user and group from the builder stage
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the compiled application binary from the builder stage
COPY --from=builder /ssso-alt-server /usr/local/bin/ssso-alt-server

# Set the user to run the application
USER appuser

# Expose the port the application runs on (default 8080, same as main SSSO, can be configured)
# This port will be mapped differently in docker-compose if running simultaneously.
EXPOSE 8080

# Default Environment variables for ssso-alt (can be overridden in docker-compose or runtime)
# These ensure it defaults to using DTS if not specified.
ENV SSSO_ALT_STORAGE_BACKEND="dts"
ENV SSSO_DTS_CLIENT_ADDRESS="ssso-dts:50051" # Internal Docker network hostname for DTS service
ENV SSSO_HTTP_ADDR="0.0.0.0:8080" # From original SSSO config defaults
# Other SSSO config (MongoURI, IssuerURL etc.) would be needed from environment or config files.

# Command to run the application
ENTRYPOINT ["/usr/local/bin/ssso-alt-server"]
