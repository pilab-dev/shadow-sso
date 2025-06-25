.PHONY: help proto clean tidy test build

# Path to the buf executable. Assumes buf is in the system PATH.
BUF := buf

# Go command
GO := go

# Default target executed when you just run make
default: help

help:
	@echo "Available targets:"
	@echo "  proto         - Generate Go code from Protocol Buffer definitions using buf"
	@echo "  clean         - Remove generated code and build artifacts"
	@echo "  tidy          - Run go mod tidy"
	@echo "  test          - Run unit tests"
	@echo "  build         - Build the ssoctl CLI application (example)"
    # Add more targets as needed (lint, docker, etc.)

proto: ## Generate Go code from Protocol Buffer definitions
	@echo "Generating Go code from Protocol Buffers..."
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
	$(GO) test ./... -v
	@echo "Tests complete."

# Example build target for the CLI. Adjust path to main.go if needed.
build: proto tidy ## Build the ssoctl CLI application
	@echo "Building ssoctl CLI..."
	$(GO) build -o sssoctl ./apps/sssoctl/sssoctl.go
	$(GO) build -o ssso ./apps/ssso/ssso.go
	@echo "ssoctl build complete. Executable: ./sssoctl and ./ssso"
