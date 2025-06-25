# SSSO Backend Enhancement TODO List

This document outlines potential enhancements based on the initial CI/CD and Kubernetes setup.

## I. CI/CD Workflow Enhancements

-   [ ] **Semantic Versioning & Release Automation:**
    -   [ ] Integrate `semantic-release` or conventional commits.
    -   [ ] Automate version bumping and GitHub Release creation on merge to `main`/`v1`.
    -   [ ] Update `publish-v1.yaml` to tag Docker images with semantic versions (e.g., `1.2.3`) alongside `:v1`.
-   [ ] **Automated Helm Chart Publishing:**
    -   [ ] Add step to `publish-v1.yaml` (or new workflow) to package Helm chart.
    -   [ ] Publish Helm chart to a chosen repository (GitHub Pages, ChartMuseum, OCI).
-   [ ] **Integration/End-to-End Tests:**
    -   [ ] Add a new job to `ci.yaml` for integration/E2E tests.
    -   [ ] Use Docker Compose or Kind to set up the application and dependencies.
    -   [ ] Define and run test suites against the live environment.
-   [ ] **Security Scanning:**
    -   [ ] Integrate image scanning (e.g., Trivy) into `ci.yaml` (on PR) and `publish-v1.yaml` (before push).
    -   [ ] Add SAST for Go code (e.g., CodeQL, SonarQube scanner).
-   [ ] **Linting:**
    -   [ ] Add explicit linting step in `ci.yaml`:
        -   [ ] Go code: `golangci-lint run`
        -   [ ] Dockerfile: `hadolint Dockerfile`
        -   [ ] Helm chart: `helm lint ./helm/ssso-backend/` (already conceptualized, make explicit)
        -   [ ] Consider `yamllint` for YAML files.
-   [ ] **Matrix Builds (Optional):**
    -   [ ] Evaluate need for testing against multiple Go versions or OS.
    -   [ ] Implement matrix strategy in `ci.yaml` if needed.

## II. Helm Chart Improvements

-   [ ] **MongoDB Subchart Integration:**
    -   [ ] Add Bitnami MongoDB chart as a conditional dependency in `helm/ssso-backend/Chart.yaml`.
    -   [ ] Expose key MongoDB configuration options in `helm/ssso-backend/values.yaml` under the `mongodb:` key, mapping them to the subchart's values.
    -   [ ] Update `templates/mongodb-placeholder.yaml` and `NOTES.txt` to reflect this direct integration.
-   [ ] **Sophisticated Readiness/Liveness Probes:**
    -   [ ] Review application startup logic and dependencies.
    -   [ ] Enhance `/readyz` in the Go application to check all critical components beyond just MongoDB ping (e.g., cache readiness, external service connectivity if any).
-   [ ] **NetworkPolicies:**
    -   [ ] Define `NetworkPolicy` resources in `helm/ssso-backend/templates/`.
    -   [ ] Add values in `values.yaml` to enable/configure NetworkPolicies.
    -   [ ] Start with a default-deny policy and allow necessary ingress/egress.
-   [ ] **PodDisruptionBudgets (PDBs):**
    -   [ ] Define `PodDisruptionBudget` in `helm/ssso-backend/templates/`.
    -   [ ] Add values in `values.yaml` to enable/configure PDBs (e.g., `minAvailable` or `maxUnavailable`).
-   [ ] **Init Containers (Example: DB Migrations):**
    -   [ ] If database migrations are needed, create an init container in `deployment.yaml`.
    -   [ ] The init container would use a separate image or the app image with a different command to run migrations.
    -   [ ] Ensure the main app container only starts after migrations succeed.
-   [ ] **External Secrets Management:**
    -   [ ] Research and choose a secrets management tool (ExternalSecrets Operator, Vault).
    -   [ ] Update documentation (`NOTES.txt`, `README.md`) to guide users on integrating with the chosen tool for `signingKeySecretName` and MongoDB credentials.
    -   [ ] Potentially add placeholder manifests or commented-out examples for `ExternalSecret` resources.
-   [ ] **Helm Chart Testing:**
    -   [ ] Implement basic chart tests using `helm test`.
    -   [ ] Create test pods/jobs in `helm/ssso-backend/templates/tests/` to verify application functionality post-deployment.

## III. Observability

-   [ ] **Structured Logging (Verification):**
    -   [ ] Confirm all log output from the Go application is structured (e.g., JSON via zerolog).
    -   [ ] Ensure log levels are consistently applied and configurable.
-   [ ] **Metrics:**
    -   [ ] Instrument Go application with Prometheus metrics (e.g., using `promhttp` handler, custom metrics for business logic).
        -   [ ] HTTP request rates/latency.
        -   [ ] Error rates.
        -   [ ] Go runtime statistics.
    -   [ ] Add a `ServiceMonitor` template in `helm/ssso-backend/templates/` (conditional on Prometheus Operator being present).
    -   [ ] Add values in `values.yaml` to enable/configure `ServiceMonitor` creation.
-   [ ] **Tracing:**
    -   [ ] Implement OpenTelemetry SDK in the Go application.
    -   [ ] Add tracing middleware for incoming requests and instrument outgoing calls (e.g., to MongoDB).
    -   [ ] Configure an exporter (e.g., Jaeger, OpenTelemetry Collector).

## IV. Developer Experience

-   [ ] **Makefile Enhancements:**
    -   [ ] `make docker-build`: Build local Docker image.
    -   [ ] `make docker-run`: Run application locally using Docker, perhaps with a MongoDB container.
    -   [ ] `make helm-lint`: Lint the Helm chart.
    -   [ ] `make helm-install-dev`: Install Helm chart to a local dev Kubernetes cluster (e.g., Kind, Minikube) with development-specific values.
    -   [ ] `make helm-upgrade-dev`: Upgrade existing dev Helm release.
    -   [ ] `make kind-cluster`: Script to create a local Kind cluster.
-   [ ] **Local Development Environment with Docker Compose:**
    -   [ ] Create a `docker-compose.yaml` file.
    -   [ ] Define services for `ssso-backend` and `mongodb`.
    -   [ ] Include volume mounts for live code reloading if possible for Go.
-   [ ] **Live Reloading for Kubernetes (Optional):**
    -   [ ] Evaluate Tilt or Skaffold for local Kubernetes development workflow.
    -   [ ] Create configuration files for the chosen tool if adopted.

## V. Application-Specific Enhancements (Go)

-   [ ] **Graceful Shutdown (Verification):**
    -   [ ] Thoroughly review `internal/server/connectrpc_server.go` and any other server entrypoints.
    -   [ ] Ensure SIGINT/SIGTERM signals trigger a graceful shutdown:
        -   Stop accepting new requests.
        -   Wait for in-flight requests to complete (with a timeout).
        -   Close database connections (`mongodb.CloseMongoDB`).
        -   Close other resources.
-   [ ] **Configuration Management (Viper Deep Dive):**
    -   [ ] Verify Viper is used effectively for all configuration points in `apps/ssso/config.go`.
    -   [ ] Ensure clear precedence of config sources (e.g., file -> env vars -> flags).
    -   [ ] Document all available configuration options clearly.
-   [ ] **Database Migration Strategy:**
    -   [ ] If the application schema evolves, implement a database migration strategy (e.g., using `golang-migrate/migrate`).
    -   [ ] Integrate migration execution into the deployment process (e.g., via init container in Helm or a manual step).

This TODO list can be used to track future work and progressively improve the SSSO backend project.
