# SSSO Distributed Token Store (DTS) Service

The SSSO-DTS is a gRPC service designed to provide a high-performance, persistent key-value storage solution primarily for session data, OIDC flows, and various tokens used within the SSSO ecosystem. It uses BBoltDB as its underlying storage engine.

## Overview

This service acts as an alternative to using Redis or direct database calls for state that needs to be shared and rapidly accessed, particularly in distributed SSSO deployments.

**Features:**

*   **gRPC Interface:** Exposes a Protobuf-defined service for storing and retrieving data.
*   **BBoltDB Backend:** Uses BBoltDB for on-disk persistence.
*   **TTL Management:** Supports Time-To-Live for stored items, with automatic cleanup of expired entries.
*   **Configurable:** Key parameters like DB path, gRPC address, and TTL settings are configurable via environment variables.

## Running the Service

### Prerequisites

*   Go (version 1.21+ recommended for building)
*   Docker (for containerized deployment)

### Building from Source

To build the `ssso-dts-server` binary:

```bash
# Navigate to the root of the SSSO project
cd /path/to/your/ssso-project/

# Build the DTS service
CGO_ENABLED=0 GOOS=linux go build -o ./bin/ssso-dts-server ./apps/ssso-dts/cmd/server
```

### Running with Docker

A `Dockerfile` is provided within this directory (`apps/ssso-dts/Dockerfile`).

1.  **Build the Docker image:**
    ```bash
    # Navigate to the root of the SSSO project
    docker build -t pilab/ssso-dts:latest -f ./apps/ssso-dts/Dockerfile .
    ```

2.  **Run the Docker container:**
    ```bash
    docker run -d \
      -p 50051:50051 \
      -v /path/on/host/data:/data \
      --name ssso-dts-container \
      pilab/ssso-dts:latest
    ```
    *   Replace `/path/on/host/data` with a directory on your Docker host where BBoltDB data should be persisted.
    *   The service inside the container will store its `dts.db` file in `/data/dts.db`.

### Configuration

The service is configured using environment variables:

*   `DTS_GRPC_SERVER_ADDRESS`: The address and port for the gRPC server to listen on.
    *   Default: `0.0.0.0:50051`
*   `DTS_BBOLTDB_PATH`: The file system path for the BBoltDB database file.
    *   Default: `/data/dts.db` (ensure this path is writable and persistent, especially in containers)
*   `DTS_DEFAULT_TTL_SECONDS`: Default Time-To-Live for items in seconds if not specified in the request.
    *   Default: `3600` (1 hour)
*   `DTS_CLEANUP_INTERVAL_SECONDS`: How often the cleanup routine for expired items runs, in seconds.
    *   Default: `600` (10 minutes)
*   `DTS_MAX_MSG_SIZE_BYTES`: Maximum message size for gRPC requests and responses.
    *   Default: `16777216` (16 MB)

Example of running with custom configuration:
```bash
docker run -d \
  -p 50052:50052 \
  -v /my/dts-data:/data \
  -e DTS_GRPC_SERVER_ADDRESS="0.0.0.0:50052" \
  -e DTS_DEFAULT_TTL_SECONDS="7200" \
  --name ssso-dts-custom \
  pilab/ssso-dts:latest
```

## Development

The core logic is split into:

*   `cmd/server/main.go`: Entry point, gRPC server setup.
*   `internal/service/dts_service.go`: Implementation of the gRPC service methods.
*   `internal/storage/bboltdb.go`: Wrapper around BBoltDB for data storage and TTL management.
*   `config/config.go`: Configuration loading.
*   `proto/dts/v1/dts.proto`: gRPC service and message definitions (in the main project's `proto` directory).

Generated Go code from the `.proto` files will be in `gen/proto/dts/v1/`. Ensure you run `buf generate` from the project root if you modify the proto definitions.
```bash
# From the root of the SSSO project
buf generate
```

This completes the initial implementation of the `ssso-dts` service components.
The next steps involve creating a client for this service within the main SSSO application, adapting repositories, and testing.
