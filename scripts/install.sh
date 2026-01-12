#!/bin/bash

set -e

REPO="ArmisSecurity/armis-cli"
BINARY_NAME="armis-cli"
VERSION="${1:-latest}"
VERIFY="${VERIFY:-true}"

validate_version() {
    local ver="$1"
    if [ "$ver" = "latest" ]; then
        return 0
    fi
    # Allow: v1.0.0, 1.0.0, v1.0.0-beta.1, 1.0.0-rc1
    if ! echo "$ver" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
        echo "Error: Invalid version format: $ver"
        echo "Expected format: v1.2.3 or 1.2.3 (optionally with suffix like -beta.1)"
        exit 1
    fi
}

validate_install_dir() {
    local dir="$1"

    if [ -z "$dir" ]; then
        echo "Error: Install directory cannot be empty" >&2
        exit 1
    fi

    case "$dir" in
        /*) ;;  # Must be absolute path
        *)
            echo "Error: Install directory must be an absolute path: $dir" >&2
            exit 1
            ;;
    esac

    # Only allow safe characters: alphanumeric, underscore, hyphen, dot, forward slash
    # This blocks shell metacharacters that could enable command injection
    if ! printf '%s' "$dir" | grep -qE '^[a-zA-Z0-9/_.-]+$'; then
        echo "Error: Install directory contains invalid characters: $dir" >&2
        echo "Only alphanumeric characters, underscores, hyphens, dots, and forward slashes are allowed." >&2
        exit 1
    fi

    # Disallow parent directory traversal segments like "../" or "/../"
    # This allows valid paths with ".." in filenames (e.g., /opt/app..v1/bin)
    case "$dir" in
        */../*|../*|*/..)
            echo "Error: Install directory cannot contain parent directory segment '..': $dir" >&2
            exit 1
            ;;
    esac
}

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

add_to_path() {
    local dir="$1"
    local shell_name=$(basename "$SHELL")
    local rc_file=""
    local path_line="export PATH=\"$dir:\$PATH\""
    
    # Skip in CI/CD environments
    if is_ci_environment; then
        echo "ℹ️  CI/CD environment detected, skipping PATH modification"
        return 0
    fi
    
    # Detect shell config file
    case "$shell_name" in
        zsh)
            rc_file="$HOME/.zshrc"
            ;;
        bash)
            if [ "$(uname -s)" = "Darwin" ]; then
                rc_file="$HOME/.bash_profile"
            else
                rc_file="$HOME/.bashrc"
            fi
            ;;
        fish)
            rc_file="$HOME/.config/fish/config.fish"
            path_line="set -gx PATH \"$dir\" \$PATH"
            ;;
        *)
            echo "⚠️  Unknown shell: $shell_name"
            echo "   Please manually add '$dir' to your PATH"
            return 1
            ;;
    esac
    
    # Check if already in config file
    if [ -f "$rc_file" ] && grep -q "$dir" "$rc_file" 2>/dev/null; then
        echo "ℹ️  PATH already configured in $rc_file"
        return 0
    fi
    
    # Add to config file
    echo ""
    echo "📝 Adding $dir to PATH in $rc_file..."
    
    # Create config file directory if it doesn't exist (for fish)
    mkdir -p "$(dirname "$rc_file")" 2>/dev/null || true
    
    echo "$path_line" >> "$rc_file" || {
        echo "❌ Failed to update $rc_file"
        return 1
    }
    
    echo "✅ PATH updated in $rc_file"
    return 0
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

is_ci_environment() {
    [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${GITLAB_CI:-}" ] || [ -n "${JENKINS_HOME:-}" ] || [ -n "${CIRCLECI:-}" ]
}

choose_install_dir() {
    # Allow override via environment variable
    if [ -n "${INSTALL_DIR:-}" ]; then
        validate_install_dir "$INSTALL_DIR"
        echo "$INSTALL_DIR"
        return
    fi
    
    # Strategy: Prefer directories already in PATH to avoid shell restart
    
    # 1. Check if /usr/local/bin is writable (common on macOS with Homebrew)
    if [ -d "$SYSTEM_BIN" ] && [ -w "$SYSTEM_BIN" ]; then
        echo "$SYSTEM_BIN"
        return
    fi
    
    # 2. Check if ~/.local/bin exists and is already in PATH
    if [ -d "$USER_BIN" ] && is_in_path "$USER_BIN"; then
        echo "$USER_BIN"
        return
    fi
    
    # 3. Try to create ~/.local/bin if it doesn't exist
    if [ ! -d "$USER_BIN" ] && mkdir -p "$USER_BIN" 2>/dev/null; then
        if is_in_path "$USER_BIN"; then
            echo "$USER_BIN"
            return
        fi
    fi
    
    # 4. Fall back to /usr/local/bin (will require sudo if not writable)
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
    
    local expected_checksum
    expected_checksum=$(awk -v filename="$(basename "$archive_file")" '$2 == filename {print $1}' "$checksums_file")
    
    if [ -z "$expected_checksum" ]; then
        echo "⚠️  Could not find checksum for $(basename "$archive_file") in checksums file"
        return 1
    fi
    
    local actual_checksum
    if command -v sha256sum > /dev/null 2>&1 && sha256sum --version > /dev/null 2>&1; then
        actual_checksum=$(sha256sum "$archive_file" | awk '{print $1}')
    elif command -v shasum > /dev/null 2>&1; then
        actual_checksum=$(shasum -a 256 "$archive_file" | awk '{print $1}')
    else
        echo "⚠️  No checksum tool found (sha256sum or shasum), skipping checksum verification"
        return 0
    fi
    
    if [ "$expected_checksum" != "$actual_checksum" ]; then
        echo "❌ Checksum verification failed!"
        echo "   Expected: $expected_checksum"
        echo "   Got:      $actual_checksum"
        return 1
    fi
    
    echo "✓ Checksums verified successfully"
}

main() {
    echo "Installing Armis CLI..."
    echo ""

    validate_version "$VERSION"

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

    TARGET_PATH="$INSTALL_DIR/$BINARY_NAME"
    
    # Check if upgrading existing installation
    EXISTING_VERSION=""
    if [ -f "$TARGET_PATH" ]; then
        EXISTING_VERSION=$("$TARGET_PATH" --version 2>/dev/null | head -n1 || echo "")
        if [ -n "$EXISTING_VERSION" ]; then
            echo "📦 Upgrading existing installation..."
            echo "   Current: $EXISTING_VERSION"
        else
            echo "📦 Replacing existing installation..."
        fi
    else
        echo "📦 Installing to $INSTALL_DIR..."
    fi
    
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

    # Get installed version
    INSTALLED_VERSION=$("$TARGET_PATH" --version 2>/dev/null | head -n1 || echo "unknown")
    
    echo ""
    echo "✅ Armis CLI installed successfully!"
    echo "   Location: $TARGET_PATH"
    echo "   Version: $INSTALLED_VERSION"
    echo ""
    
    # Refresh command hash table for current shell
    hash -r 2>/dev/null || rehash 2>/dev/null || true
    
    # Check if command is now available
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        # Success! Command is in PATH and discoverable
        if is_in_path "$INSTALL_DIR"; then
            echo "🎉 Ready to use! The command is available in your PATH."
            echo ""
            echo "   Try it now: $BINARY_NAME --help"
            echo ""
            if [ -t 0 ] && [ -z "${CI:-}" ]; then
                echo "💡 Note: If you have other terminal windows open, you may need to:"
                echo "   • Run 'hash -r' in those terminals, or"
                echo "   • Open new terminal windows"
            fi
        else
            echo "✅ Command is available!"
        fi
    else
        # Command not in PATH yet
        echo "⚠️  Installation complete, but '$BINARY_NAME' is not in your PATH yet."
        echo ""
        
        if ! is_in_path "$INSTALL_DIR"; then
            # Need to add to PATH
            if add_to_path "$INSTALL_DIR"; then
                echo ""
                echo "📋 To use $BINARY_NAME, you need to reload your shell configuration:"
                echo ""
                local shell_name=$(basename "$SHELL")
                case "$shell_name" in
                    zsh)
                        echo "   source ~/.zshrc"
                        ;;
                    bash)
                        if [ "$(uname -s)" = "Darwin" ]; then
                            echo "   source ~/.bash_profile"
                        else
                            echo "   source ~/.bashrc"
                        fi
                        ;;
                    fish)
                        echo "   source ~/.config/fish/config.fish"
                        ;;
                    *)
                        echo "   (or open a new terminal window)"
                        ;;
                esac
                echo ""
                echo "   Or open a new terminal window."
                echo ""
                echo "   You can also run it directly: $TARGET_PATH --help"
            else
                # Failed to add to PATH
                print_path_help "$INSTALL_DIR"
                echo ""
                echo "You can run it directly: $TARGET_PATH --help"
                exit 1
            fi
        else
            # Directory is in PATH but command not found (hash table issue)
            echo "   PATH contains $INSTALL_DIR, but the command isn't cached yet."
            echo ""
            echo "   Run: hash -r"
            echo "   Or open a new terminal window."
            echo ""
            echo "   You can also run it directly: $TARGET_PATH --help"
        fi
    fi
}

main
