.PHONY: build install clean test lint help

BINARY_NAME=armis
BUILD_DIR=bin
GO=go
GOFLAGS=-ldflags="-s -w"

help:
	@echo "Available targets:"
	@echo "  build      - Build the binary"
	@echo "  install    - Install the binary to GOPATH/bin"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run tests"
	@echo "  lint       - Run linters"
	@echo "  release    - Build for multiple platforms"

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/armis

install:
	@echo "Installing $(BINARY_NAME)..."
	$(GO) install $(GOFLAGS) ./cmd/armis

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	$(GO) clean

test:
	@echo "Running tests..."
	$(GO) test -v ./...

lint:
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed" && exit 1)
	golangci-lint run

release:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/armis
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/armis
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/armis
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/armis
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/armis
	@echo "Release builds complete in $(BUILD_DIR)/"
