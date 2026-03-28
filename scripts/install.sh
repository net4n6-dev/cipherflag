#!/bin/sh
# CipherFlag installer — downloads the latest CLI binary.
# Usage: curl -fsSL https://raw.githubusercontent.com/cyberflag-ai/cipherflag/main/scripts/install.sh | sh

set -e

REPO="cyberflag-ai/cipherflag"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux|darwin) ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

BINARY="cipherflag-${OS}-${ARCH}"

echo "CipherFlag Installer"
echo "──────────────────────"
echo "  OS:   $OS"
echo "  Arch: $ARCH"
echo ""

# Get latest release tag
echo "  Finding latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "  ✗ Failed to find latest release"
    echo "  Check: https://github.com/${REPO}/releases"
    exit 1
fi

echo "  Latest: $LATEST"

# Download binary
URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}"
echo "  Downloading ${BINARY}..."

TMP=$(mktemp)
if ! curl -fsSL -o "$TMP" "$URL"; then
    echo "  ✗ Download failed"
    echo "  URL: $URL"
    rm -f "$TMP"
    exit 1
fi

chmod +x "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "${INSTALL_DIR}/cipherflag"
else
    echo "  Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$TMP" "${INSTALL_DIR}/cipherflag"
fi

echo ""
echo "  ✓ Installed cipherflag to ${INSTALL_DIR}/cipherflag"
echo ""
echo "  Get started:"
echo "    cipherflag setup"
echo ""
