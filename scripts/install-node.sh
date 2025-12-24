#!/bin/bash
#
# Rift Node Installer
#
# Installs the Rift mesh VPN client on Linux and macOS.
#
# Usage:
#   curl -fsSL https://bmo.guru/rift/install-node.sh | sudo bash
#
# Options:
#   --version VERSION   Install specific version (default: latest)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Detect OS
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="macos" ;;
    *)       echo "Unsupported OS: $OS_TYPE"; exit 1 ;;
esac

# Config
INSTALL_DIR="/usr/local/bin"
if [[ "$OS" == "macos" ]]; then
    CONFIG_DIR="$HOME/.config/rift"
else
    CONFIG_DIR="/etc/rift"
fi

GITHUB_REPO="b33bmo/rift"
DOWNLOAD_BASE="https://bmo.guru/rift/releases"

# Parse args
VERSION="latest"
while [[ $# -gt 0 ]]; do
    case $1 in
        --version) VERSION="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Run with sudo: sudo bash install-node.sh"
        exit 1
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    log_info "Detected: $OS $ARCH"
}

download_binary() {
    log_info "Downloading rift..."

    # Check for local build
    if [[ -f "./target/release/rift" ]]; then
        cp ./target/release/rift "$INSTALL_DIR/rift"
        log_success "Installed from local build"
        chmod 755 "$INSTALL_DIR/rift"
        return
    fi

    local BINARY_NAME="rift-${OS}-${ARCH}"
    local DOWNLOAD_URL

    if [[ "$VERSION" == "latest" ]]; then
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}"
    else
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${BINARY_NAME}"
    fi

    log_info "Fetching from: $DOWNLOAD_URL"

    if curl -fsSL -o /tmp/rift "$DOWNLOAD_URL" 2>/dev/null; then
        mv /tmp/rift "$INSTALL_DIR/rift"
        log_success "Downloaded from GitHub"
    elif curl -fsSL -o /tmp/rift "${DOWNLOAD_BASE}/${BINARY_NAME}" 2>/dev/null; then
        mv /tmp/rift "$INSTALL_DIR/rift"
        log_success "Downloaded from bmo.guru"
    else
        log_error "Download failed. Build from source:"
        echo "  git clone https://github.com/$GITHUB_REPO"
        echo "  cd rift && cargo build --release"
        echo "  sudo cp target/release/rift /usr/local/bin/"
        exit 1
    fi

    chmod 755 "$INSTALL_DIR/rift"
    log_success "Installed to $INSTALL_DIR/rift"
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       Rift Installation Complete        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo "Quick start:"
    echo ""
    echo "  1. Initialize config:"
    echo -e "     ${BLUE}rift init -n my-node -b beacon.example.com:7770${NC}"
    echo ""
    echo "  2. Connect to VPN:"
    echo -e "     ${BLUE}sudo rift connect${NC}"
    echo ""
    echo "  3. Disconnect:"
    echo -e "     Press ${BLUE}Ctrl+C${NC}"
    echo ""
    echo "Other commands:"
    echo "  rift status   - Show status"
    echo "  rift peers    - List peers"
    echo "  rift key      - Show public key"
    echo ""
}

main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Rift Installer                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    detect_arch
    download_binary
    print_summary
}

main "$@"
