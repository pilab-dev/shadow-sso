## Project Overview

This project is a Go-based OAuth 2.0 and OpenID Connect (OIDC) server called Shadow SSO (3SO). It provides a complete suite of tools to implement secure authentication and authorization in Go applications. It can be used as a standalone server or as a library.

The project is designed to be modular and flexible, with support for various grant types, token management features, and integration with external identity providers like LDAP/Active Directory. It uses MongoDB for data storage by default but also offers a high-performance Distributed Token Store (DTS) backend using BBoltDB.

The project also includes a command-line interface (CLI) tool called `ssoctl` for managing the SSO system.

## Building and Running

The project uses a `Makefile` for common development tasks.

### Building

To build the `ssso` server and `ssoctl` CLI applications, run:

```bash
make build
```

This will create the `ssso` and `ssoctl` executables in the project's root directory.

### Running

The `ssso` server can be run in several ways:

**1. Standalone:**

After building the application, you can run it directly:

```bash
./ssso
```

The server requires a configuration file (`sso_config.yaml`) or environment variables to be set. Key configuration options include the MongoDB connection string, issuer URL, and token signing key.

**2. Docker:**

A `Dockerfile` is provided to build a Docker image for the `ssso` server:

```bash
docker build -t pilab/ssso:latest .
```

You can then run the container with the required environment variables:

```bash
docker run -d \
  -p 8080:8080 \
  -e SSSO_MONGO_URI="mongodb://your_mongo_host:27017/shadow_sso_db" \
  -e SSSO_ISSUER_URL="http://localhost:8080" \
  -e SSSO_SIGNING_KEY_PATH="/path/to/your/signing_key.pem" \
  --name ssso-server \
  pilab/ssso:latest
```

**3. Docker Compose:**

The project includes a `docker-compose.yml` file to run the `ssso` server with the Distributed Token Store (`ssso-dts`) and a MongoDB instance:

```bash
docker-compose up --build
```

### Testing

To run the unit tests, use the following command:

```bash
make test
```

## Development Conventions

*   **Code Generation:** The project uses Protocol Buffers and `buf` to generate Go code for API definitions. The `make proto` command can be used to regenerate the code.
*   **Dependency Management:** Go modules are used for dependency management. The `go.mod` file lists the project's dependencies.
*   **Configuration:** The server and CLI tool are configured using Viper, which allows for configuration via files (e.g., `sso_config.yaml`) or environment variables.
*   **Interfaces:** The project defines several interfaces (`OAuthRepository`, `UserRepository`, `TokenStore`) to allow for custom implementations of storage and caching layers. The default implementation uses MongoDB.
*   **CLI:** The `ssoctl` CLI is built using Cobra, a popular library for creating CLI applications in Go.

## Key Files

*   `README.md`: Provides a comprehensive overview of the project, its features, and how to use it.
*   `Makefile`: Contains commands for building, testing, and other development tasks.
*   `go.mod`: Defines the project's Go module and its dependencies.
*   `apps/ssso/ssso.go`: The main entry point for the `ssso` server application.
*   `apps/sssoctl/sssoctl.go`: The main entry point for the `ssoctl` CLI tool.
*   `apps/ssso/config/config.go`: Defines the configuration structure for the `ssso` server.
*   `domain/`: Contains the core domain models and interfaces for the application.
*   `mongodb/`: Contains the MongoDB implementation of the repository interfaces.
*   `services/`: Contains the business logic and services for the application.
*   `api/`: Contains the API handlers for the server.
*   `proto/`: Contains the Protocol Buffer definitions for the API.
