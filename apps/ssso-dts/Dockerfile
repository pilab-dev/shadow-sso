# Step 1: Build the application
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY ../../go.mod ../../go.sum ./
RUN go mod download

# Copy the entire project
# Adjust the source path according to your project structure
# Assuming this Dockerfile is in apps/ssso-dts/
COPY ../../ ./

# Build the DTS service
# The main package for ssso-dts is apps/ssso-dts/cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/ssso-dts-server ./apps/ssso-dts/cmd/server

# Step 2: Create the runtime image
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/ssso-dts-server /app/ssso-dts-server

# Create a non-root user and group
RUN addgroup -S dtsgroup && adduser -S dtsuser -G dtsgroup
RUN chown -R dtsuser:dtsgroup /app
# Create data directory and set permissions
RUN mkdir -p /data && chown -R dtsuser:dtsgroup /data

USER dtsuser

# Expose the gRPC port (adjust if your config uses a different port)
EXPOSE 50051

# Set default environment variables (can be overridden at runtime)
ENV DTS_GRPC_SERVER_ADDRESS="0.0.0.0:50051"
ENV DTS_BBOLTDB_PATH="/data/dts.db"
ENV DTS_DEFAULT_TTL_SECONDS="3600"
ENV DTS_CLEANUP_INTERVAL_SECONDS="600"
ENV DTS_MAX_MSG_SIZE_BYTES="16777216" # 16MB

# Command to run the application
ENTRYPOINT ["/app/ssso-dts-server"]
