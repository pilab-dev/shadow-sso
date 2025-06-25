# Stage 1: Build the Go application
FROM golang:1.24.4-alpine AS builder

# Set necessary environment variables
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Create appuser
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project source code
COPY . .

# Build the server application
# The main application seems to be in apps/ssso/ssso.go based on the README
RUN go build -ldflags="-w -s" -o /ssso ./apps/ssso/

# Stage 2: Create the final lightweight image
FROM alpine:latest

# Import the user and group from the builder stage
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the compiled application binary from the builder stage
COPY --from=builder /ssso /usr/local/bin/ssso

# Copy configuration files or templates if any (assuming config is mounted or handled externally)
# For example, if you have a default config:
# COPY --from=builder /app/sso_config.yaml.example /etc/sso/sso_config.yaml

# Set the user to run the application
USER appuser

# Expose the port the application runs on (default 8080, can be configured)
EXPOSE 8080

# Command to run the application
ENTRYPOINT ["/usr/local/bin/ssso"]
