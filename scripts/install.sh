#!/bin/bash

set -e

REPO="silk-security/Moose-CLI"
BINARY_NAME="armis-cli"
INSTALL_DIR="/usr/local/bin"

detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        linux*)  echo "linux" ;;
        darwin*) echo "darwin" ;;
        msys*|mingw*|cygwin*) echo "windows" ;;
        *) echo "unsupported" ;;
    esac
}

detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

main() {
    echo "Installing Armis Security Scanner CLI..."
    echo ""

    OS=$(detect_os)
    ARCH=$(detect_arch)

    if [ "$OS" = "unsupported" ] || [ "$ARCH" = "unsupported" ]; then
        echo "Error: Unsupported operating system or architecture"
        echo "OS: $(uname -s), Arch: $(uname -m)"
        exit 1
    fi

    echo "Detected OS: $OS"
    echo "Detected Architecture: $ARCH"
    echo ""

    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    
    if [ "$OS" = "windows" ]; then
        DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
        BINARY_NAME="${BINARY_NAME}.exe"
    fi

    echo "Downloading from: $DOWNLOAD_URL"
    
    TMP_FILE=$(mktemp)
    
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE"
    elif command -v wget > /dev/null 2>&1; then
        wget -q "$DOWNLOAD_URL" -O "$TMP_FILE"
    else
        echo "Error: Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    chmod +x "$TMP_FILE"

    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
    else
        echo "Installing to $INSTALL_DIR requires sudo privileges..."
        sudo mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
    fi

    echo ""
    echo "✓ Armis CLI installed successfully to $INSTALL_DIR/$BINARY_NAME"
    echo ""
    echo "Run 'armis-cli --help' to get started"
}

main
