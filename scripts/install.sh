#!/bin/bash

set -e

REPO="ArmisSecurity/armis-cli"
BINARY_NAME="armis-cli"
INSTALL_DIR="/usr/local/bin"
VERSION="${1:-latest}"
VERIFY="${VERIFY:-true}"

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

download_file() {
    local url="$1"
    local output="$2"
    
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget > /dev/null 2>&1; then
        wget -q "$url" -O "$output"
    else
        echo "Error: Neither curl nor wget found. Please install one of them."
        exit 1
    fi
}

verify_checksums() {
    local archive_file="$1"
    local checksums_file="$2"
    local checksums_sig="$3"
    
    if [ "$VERIFY" != "true" ]; then
        echo "⚠️  Skipping verification (VERIFY=false)"
        return 0
    fi
    
    if command -v cosign > /dev/null 2>&1; then
        echo "🔐 Verifying signature with cosign..."
        if cosign verify-blob \
            --certificate-identity-regexp 'https://github.com/ArmisSecurity/armis-cli/.github/workflows/release.yml@refs/tags/.*' \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            --signature "$checksums_sig" \
            "$checksums_file" > /dev/null 2>&1; then
            echo "✓ Signature verified successfully"
        else
            echo "⚠️  Signature verification failed, falling back to checksum verification"
        fi
    else
        echo "ℹ️  cosign not found, verifying checksums only"
        echo "   Install cosign for full signature verification: https://docs.sigstore.dev/cosign/installation/"
    fi
    
    echo "🔍 Verifying checksums..."
    if command -v sha256sum > /dev/null 2>&1; then
        grep "$(basename "$archive_file")" "$checksums_file" | sha256sum -c --status
    elif command -v shasum > /dev/null 2>&1; then
        grep "$(basename "$archive_file")" "$checksums_file" | shasum -a 256 -c --status
    else
        echo "⚠️  No checksum tool found (sha256sum or shasum), skipping checksum verification"
        return 0
    fi
    
    echo "✓ Checksums verified successfully"
}

main() {
    echo "Installing Armis CLI..."
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

    if [ "$VERSION" = "latest" ]; then
        BASE_URL="https://github.com/${REPO}/releases/latest/download"
    else
        BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    fi
    
    ARCHIVE_NAME="${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    if [ "$OS" = "windows" ]; then
        ARCHIVE_NAME="${BINARY_NAME}-${OS}-${ARCH}.zip"
    fi
    
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT
    
    ARCHIVE_FILE="$TMP_DIR/$ARCHIVE_NAME"
    CHECKSUMS_FILE="$TMP_DIR/${BINARY_NAME}-checksums.txt"
    CHECKSUMS_SIG="$TMP_DIR/${BINARY_NAME}-checksums.txt.sig"
    
    echo "📦 Downloading $ARCHIVE_NAME..."
    download_file "$BASE_URL/$ARCHIVE_NAME" "$ARCHIVE_FILE"
    
    echo "📥 Downloading checksums..."
    download_file "$BASE_URL/${BINARY_NAME}-checksums.txt" "$CHECKSUMS_FILE"
    download_file "$BASE_URL/${BINARY_NAME}-checksums.txt.sig" "$CHECKSUMS_SIG" || true
    
    echo ""
    verify_checksums "$ARCHIVE_FILE" "$CHECKSUMS_FILE" "$CHECKSUMS_SIG"
    echo ""
    
    echo "📂 Extracting archive..."
    if [ "$OS" = "windows" ]; then
        unzip -q "$ARCHIVE_FILE" -d "$TMP_DIR"
    else
        tar -xzf "$ARCHIVE_FILE" -C "$TMP_DIR"
    fi
    
    BINARY_FILE="$TMP_DIR/$BINARY_NAME"
    if [ "$OS" = "windows" ]; then
        BINARY_FILE="${BINARY_FILE}.exe"
    fi
    
    chmod +x "$BINARY_FILE"

    echo "📥 Installing to $INSTALL_DIR..."
    if [ -w "$INSTALL_DIR" ]; then
        mv "$BINARY_FILE" "$INSTALL_DIR/$BINARY_NAME"
    else
        echo "   (requires sudo privileges)"
        sudo mv "$BINARY_FILE" "$INSTALL_DIR/$BINARY_NAME"
    fi

    echo ""
    echo "✅ Armis CLI installed successfully!"
    echo ""
    echo "Run 'armis-cli --help' to get started"
}

main
