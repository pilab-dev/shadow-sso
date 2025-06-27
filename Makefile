.PHONY: help proto clean tidy test build

# Path to the buf executable. Assumes buf is in the system PATH.
BUF := buf
GOTEST := $(shell go list ./... | grep -v /gen/ | grep -v /cmd/ | grep -v /helm/)
# Go command
GO := go

# Default target executed when you just run make
default: help

# Variables
BUF_VERSION := 1.28.1 # Specify desired buf version

help:
	@echo "Available targets:"
	@echo "  install-deps  - Install development dependencies (e.g., buf)"
	@echo "  proto         - Generate Go code from Protocol Buffer definitions using buf (installs buf if missing)"
	@echo "  clean         - Remove generated code and build artifacts"
	@echo "  tidy          - Run go mod tidy"
	@echo "  test          - Run unit tests"
	@echo "  build         - Build the ssoctl CLI application (example)"
    # Add more targets as needed (lint, docker, etc.)

install-deps: ## Install development dependencies
	@echo "Installing dependencies..."
	@mkdir -p $(HOME)/.local/bin
	@export PATH="$(HOME)/.local/bin:$$PATH"; \
	if ! command -v buf > /dev/null; then \
		echo "buf not found. Installing buf v$(BUF_VERSION) to $(HOME)/.local/bin..."; \
		GOBIN=$(HOME)/.local/bin $(GO) install github.com/bufbuild/buf/cmd/buf@v$(BUF_VERSION); \
		echo "buf installed to $(HOME)/.local/bin/buf"; \
	else \
		echo "buf is already installed: $$(buf --version)"; \
	fi
	@echo "Dependency installation check complete. Ensure $(HOME)/.local/bin is in your PATH."

proto: install-deps ## Generate Go code from Protocol Buffer definitions
	@echo "Generating Go code from Protocol Buffers..."
	@export PATH="$(HOME)/.local/bin:$$PATH"; \
	$(BUF) generate
	@echo "Proto generation complete."

# This target might need to be adjusted if other generated files exist outside 'gen/' from proto
clean: ## Remove generated code and build artifacts
	@echo "Cleaning generated files and build artifacts..."
	rm -rf ./gen
	# rm -f ./ssoctl # Example if 'build' target creates ssoctl binary at root
	@echo "Clean complete."

tidy: ## Tidy go module files
	@echo "Running go mod tidy..."
	$(GO) mod tidy
	@echo "Go mod tidy complete."

test: ## Run unit tests
	@echo "Running unit tests..."
	echo -e $(GOTEST)
	@go test $(GOTEST)
	@echo "Tests complete."

# Example build target for the CLI. Adjust path to main.go if needed.
build: tidy ## Build the ssoctl CLI application
	@echo "Building ssoctl CLI..."
	$(GO) build -o ssoctl ./apps/sssoctl/
	$(GO) build -o ssoctl ./apps/ssso/
	@echo "ssoctl build complete. Executable: ./ssoctl & ./ssso"
