.PHONY: build install clean test lint scan help tools coverage

BINARY_NAME=armis-cli
BUILD_DIR=bin
GO=go
GOFLAGS=-ldflags="-s -w"
PREFIX ?= /usr/local
INSTALL_DIR=$(PREFIX)/bin
COVERAGE_FILE=coverage.out

help:
	@echo "Available targets:"
	@echo "  build      - Build the binary"
	@echo "  install    - Install the binary to $(INSTALL_DIR)"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run tests with coverage"
	@echo "  coverage   - Show coverage report"
	@echo "  lint       - Run linters"
	@echo "  scan       - Run security scan on this repository"
	@echo "  release    - Build for multiple platforms"
	@echo "  tools      - Install dev tools (gotestsum)"

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/armis-cli

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@install -d $(INSTALL_DIR)
	@install -m 0755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✓ $(BINARY_NAME) installed successfully to $(INSTALL_DIR)/$(BINARY_NAME)"

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(COVERAGE_FILE)
	$(GO) clean

GOTESTSUM := $(shell command -v gotestsum 2>/dev/null || echo "$(shell go env GOPATH)/bin/gotestsum")

test:
	@echo "Running tests with coverage..."
	@if [ -x "$(GOTESTSUM)" ]; then \
		$(GOTESTSUM) --format testdox -- -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...; \
	else \
		echo "gotestsum not found, using go test (run 'make tools' for colored output)"; \
		$(GO) test -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...; \
	fi
	@echo ""
	@echo "Coverage summary:"
	@$(GO) tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print "  Total: " $$3}'

coverage:
	@if [ ! -f $(COVERAGE_FILE) ]; then \
		echo "No coverage file found. Run 'make test' first."; \
		exit 1; \
	fi
	@echo "Coverage by package:"
	@$(GO) tool cover -func=$(COVERAGE_FILE)

tools:
	@echo "Installing dev tools..."
	go install gotest.tools/gotestsum@v1.13.0

lint:
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed" && exit 1)
	golangci-lint run

scan:
	@echo "Running security scan..."
	@test -f $(BUILD_DIR)/$(BINARY_NAME) || (echo "Binary not found. Run 'make build' first." && exit 1)
	$(BUILD_DIR)/$(BINARY_NAME) scan repo . --fail-on CRITICAL,HIGH

release:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/armis-cli
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/armis-cli
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/armis-cli
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/armis-cli
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/armis-cli
	@echo "Release builds complete in $(BUILD_DIR)/"
