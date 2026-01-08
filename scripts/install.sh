#!/bin/bash

set -e

REPO="ArmisSecurity/armis-cli"
BINARY_NAME="armis-cli"
VERSION="${1:-latest}"
VERIFY="${VERIFY:-true}"

USER_BIN="$HOME/.local/bin"
SYSTEM_BIN="/usr/local/bin"

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

fail() {
    echo "❌ $*" >&2
    exit 1
}

is_in_path() {
    local dir="$1"
    case ":$PATH:" in
        *":$dir:"*) return 0 ;;
        *) return 1 ;;
    esac
}

print_path_help() {
    local dir="$1"
    cat <<EOF

⚠️  '$BINARY_NAME' was installed to: $dir
but '$dir' is not in your PATH, so the command may not be found.

Current PATH:
$PATH

To fix this, add the following to your shell configuration:

For zsh (default on macOS):
  echo 'export PATH="$dir:\$PATH"' >> ~/.zshrc
  source ~/.zshrc

For bash:
  echo 'export PATH="$dir:\$PATH"' >> ~/.bash_profile
  source ~/.bash_profile

Or simply open a new terminal window and try again.
EOF
}

choose_install_dir() {
    if [ -n "${INSTALL_DIR:-}" ]; then
        echo "$INSTALL_DIR"
        return
    fi
    
    if [ -d "$USER_BIN" ] || mkdir -p "$USER_BIN" 2>/dev/null; then
        if [ -w "$USER_BIN" ]; then
            echo "$USER_BIN"
            return
        fi
    fi
    
    echo "$SYSTEM_BIN"
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

    INSTALL_DIR=$(choose_install_dir)

    echo "Detected OS: $OS"
    echo "Detected Architecture: $ARCH"
    echo "Install Directory: $INSTALL_DIR"
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
    
    TARGET_PATH="$INSTALL_DIR/$BINARY_NAME"
    
    if [ -w "$INSTALL_DIR" ]; then
        mv "$BINARY_FILE" "$TARGET_PATH" || fail "Failed to move binary to $TARGET_PATH"
    else
        echo "   (requires sudo privileges)"
        sudo -v || fail "sudo authentication failed"
        sudo mv "$BINARY_FILE" "$TARGET_PATH" || fail "Failed to move binary to $TARGET_PATH (sudo mv failed)"
    fi
    
    if [ -w "$TARGET_PATH" ]; then
        chmod +x "$TARGET_PATH" 2>/dev/null || true
    else
        sudo chmod +x "$TARGET_PATH" 2>/dev/null || true
    fi
    
    [ -f "$TARGET_PATH" ] || fail "Install appeared to succeed, but $TARGET_PATH does not exist"

    echo ""
    echo "✅ Armis CLI installed to: $TARGET_PATH"
    echo ""
    
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        echo "✅ Verified: $(command -v "$BINARY_NAME")"
        echo ""
        echo "Run '$BINARY_NAME --help' to get started"
    else
        echo "⚠️  Installed, but '$BINARY_NAME' is not currently discoverable in your PATH."
        if ! is_in_path "$INSTALL_DIR"; then
            print_path_help "$INSTALL_DIR"
        else
            echo ""
            echo "PATH contains $INSTALL_DIR, but the command still isn't found."
            echo "Try running: hash -r"
            echo "Or open a new terminal window."
        fi
        echo ""
        echo "You can also run it directly: $TARGET_PATH --help"
        exit 1
    fi
}

main
