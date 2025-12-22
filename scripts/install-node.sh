#!/bin/bash
#
# Rift Node Installer
#
# This script installs the Rift mesh VPN client on Linux and macOS.
# Requires: root privileges, systemd (Linux) or launchd (macOS)
#
# Usage:
#   curl -fsSL https://bmo.guru/rift/install-node.sh | sudo bash
#   # or
#   sudo ./install-node.sh
#
# Options:
#   --beacon ADDRESS    Set beacon server address (default: prompt)
#   --name NAME         Set node name (default: hostname)
#   --no-start          Don't start the service after install
#   --version VERSION   Install specific version (default: latest)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect OS
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="macos" ;;
    *)       echo "Unsupported OS: $OS_TYPE"; exit 1 ;;
esac

# Configuration based on OS
if [[ "$OS" == "macos" ]]; then
    INSTALL_DIR="/usr/local/bin"
    CONFIG_DIR="/usr/local/etc/rift"
    RUN_DIR="/usr/local/var/run/rift"
    LIB_DIR="/usr/local/var/lib/rift"
    LAUNCHD_DIR="/Library/LaunchDaemons"
    SERVICE_NAME="com.rift.node"
else
    INSTALL_DIR="/usr/local/bin"
    CONFIG_DIR="/etc/rift"
    SYSTEMD_DIR="/etc/systemd/system"
    RUN_DIR="/var/run/rift"
    LIB_DIR="/var/lib/rift"
fi

GITHUB_REPO="bischoffdev/rift"
DOWNLOAD_BASE="https://bmo.guru/rift/releases"

# Parse arguments
BEACON_ADDR=""
NODE_NAME=""
NO_START=false
VERSION="latest"

while [[ $# -gt 0 ]]; do
    case $1 in
        --beacon)
            BEACON_ADDR="$2"
            shift 2
            ;;
        --name)
            NODE_NAME="$2"
            shift 2
            ;;
        --no-start)
            NO_START=true
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_service_manager() {
    if [[ "$OS" == "linux" ]]; then
        if ! command -v systemctl &> /dev/null; then
            log_error "systemd is required but not found"
            exit 1
        fi
    elif [[ "$OS" == "macos" ]]; then
        if ! command -v launchctl &> /dev/null; then
            log_error "launchctl not found"
            exit 1
        fi
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_info "Detected architecture: $ARCH"
}

detect_os_version() {
    if [[ "$OS" == "linux" ]]; then
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            OS_NAME=$ID
            OS_VERSION=$VERSION_ID
        else
            OS_NAME="linux"
            OS_VERSION="unknown"
        fi
    elif [[ "$OS" == "macos" ]]; then
        OS_NAME="macos"
        OS_VERSION=$(sw_vers -productVersion)
    fi
    log_info "Detected OS: $OS_NAME $OS_VERSION"
}

install_dependencies() {
    log_info "Checking dependencies..."

    if [[ "$OS" == "linux" ]]; then
        # Check for TUN support
        if [[ ! -c /dev/net/tun ]]; then
            log_warn "/dev/net/tun not found, creating..."
            mkdir -p /dev/net
            mknod /dev/net/tun c 10 200
            chmod 666 /dev/net/tun
        fi
    elif [[ "$OS" == "macos" ]]; then
        # macOS uses utun devices automatically, no setup needed
        log_info "macOS uses utun devices (auto-created)"
    fi

    # Ensure curl is available
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not found"
        exit 1
    fi

    log_success "Dependencies OK"
}

create_directories() {
    log_info "Creating directories..."
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$RUN_DIR"
    mkdir -p "$LIB_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$RUN_DIR"
    chmod 755 "$LIB_DIR"
    log_success "Directories created"
}

download_binary() {
    log_info "Downloading rift-node..."

    # Check for local build first (development)
    if [[ -f "./target/release/rift-node" ]]; then
        cp ./target/release/rift-node "$INSTALL_DIR/rift-node"
        log_success "Installed from local build"
        chmod 755 "$INSTALL_DIR/rift-node"
        return
    fi

    # Determine download URL based on OS
    local BINARY_NAME="rift-node-${OS}-${ARCH}"
    local DOWNLOAD_URL

    if [[ "$VERSION" == "latest" ]]; then
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}"
    else
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${BINARY_NAME}"
    fi

    # Try to download
    log_info "Fetching from: $DOWNLOAD_URL"

    if curl -fsSL -o /tmp/rift-node "$DOWNLOAD_URL" 2>/dev/null; then
        mv /tmp/rift-node "$INSTALL_DIR/rift-node"
        log_success "Downloaded from GitHub releases"
    elif curl -fsSL -o /tmp/rift-node "${DOWNLOAD_BASE}/${BINARY_NAME}" 2>/dev/null; then
        mv /tmp/rift-node "$INSTALL_DIR/rift-node"
        log_success "Downloaded from bmo.guru"
    else
        log_error "Failed to download binary."
        echo ""
        echo "Options:"
        echo "  1. Build from source:"
        echo "     git clone https://github.com/$GITHUB_REPO"
        echo "     cd rift && cargo build --release"
        echo "     sudo ./scripts/install-node.sh"
        echo ""
        echo "  2. Check releases at: https://github.com/$GITHUB_REPO/releases"
        exit 1
    fi

    chmod 755 "$INSTALL_DIR/rift-node"
    log_success "Binary installed to $INSTALL_DIR/rift-node"
}

install_service_linux() {
    log_info "Installing systemd service..."

    cat > "$SYSTEMD_DIR/rift-node.service" << 'EOF'
[Unit]
Description=Rift Mesh VPN Node
Documentation=https://github.com/bischoffdev/rift
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rift-node run --config /etc/rift/rift.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes

# Required capabilities for TUN device
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

# Allow access to /dev/net/tun
DeviceAllow=/dev/net/tun rw

# State directory
StateDirectory=rift
ConfigurationDirectory=rift
RuntimeDirectory=rift

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rift-node

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service installed"
}

install_service_macos() {
    log_info "Installing launchd service..."

    cat > "$LAUNCHD_DIR/${SERVICE_NAME}.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${SERVICE_NAME}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/rift-node</string>
        <string>run</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/rift.toml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/usr/local/var/log/rift-node.log</string>

    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/rift-node.error.log</string>

    <key>WorkingDirectory</key>
    <string>${LIB_DIR}</string>
</dict>
</plist>
EOF

    # Create log directory
    mkdir -p /usr/local/var/log

    log_success "Launchd service installed"
}

install_service() {
    if [[ "$OS" == "linux" ]]; then
        install_service_linux
    elif [[ "$OS" == "macos" ]]; then
        install_service_macos
    fi
}

configure_node() {
    if [[ -f "$CONFIG_DIR/rift.toml" ]]; then
        log_warn "Config file already exists, skipping configuration"
        return
    fi

    log_info "Configuring node..."

    # Get node name
    if [[ -z "$NODE_NAME" ]]; then
        NODE_NAME=$(hostname -s 2>/dev/null || hostname)
        read -p "Node name [$NODE_NAME]: " input
        NODE_NAME=${input:-$NODE_NAME}
    fi

    # Get beacon address
    if [[ -z "$BEACON_ADDR" ]]; then
        read -p "Beacon server address (host:port): " BEACON_ADDR
        if [[ -z "$BEACON_ADDR" ]]; then
            log_error "Beacon address is required"
            exit 1
        fi
    fi

    # Generate config
    "$INSTALL_DIR/rift-node" init -n "$NODE_NAME" -b "$BEACON_ADDR" -c "$CONFIG_DIR/rift.toml"

    log_success "Configuration saved to $CONFIG_DIR/rift.toml"

    # Show public key
    echo ""
    echo -e "${GREEN}Your node's public key:${NC}"
    "$INSTALL_DIR/rift-node" pubkey -c "$CONFIG_DIR/rift.toml"
    echo ""
    echo "Share this key with peers who need to connect to you."
}

start_service_linux() {
    systemctl enable rift-node
    systemctl start rift-node

    sleep 2

    if systemctl is-active --quiet rift-node; then
        log_success "rift-node is running"
    else
        log_error "rift-node failed to start. Check: journalctl -u rift-node"
        exit 1
    fi
}

start_service_macos() {
    launchctl load -w "$LAUNCHD_DIR/${SERVICE_NAME}.plist"

    sleep 2

    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_success "rift-node is running"
    else
        log_error "rift-node failed to start. Check: /usr/local/var/log/rift-node.error.log"
        exit 1
    fi
}

start_service() {
    if [[ "$NO_START" == "true" ]]; then
        log_info "Skipping service start (--no-start)"
        return
    fi

    log_info "Starting rift-node service..."

    if [[ "$OS" == "linux" ]]; then
        start_service_linux
    elif [[ "$OS" == "macos" ]]; then
        start_service_macos
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       Rift Node Installation Complete     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo "Useful commands:"
    if [[ "$OS" == "linux" ]]; then
        echo "  systemctl status rift-node    - Check status"
        echo "  journalctl -fu rift-node      - View logs"
    elif [[ "$OS" == "macos" ]]; then
        echo "  sudo launchctl list | grep rift    - Check status"
        echo "  tail -f /usr/local/var/log/rift-node.log  - View logs"
        echo "  sudo launchctl stop $SERVICE_NAME   - Stop service"
        echo "  sudo launchctl start $SERVICE_NAME  - Start service"
    fi
    echo "  rift-node ctl status          - Daemon status (via IPC)"
    echo "  rift-node peers               - List connected peers"
    echo ""
    echo "Config file: $CONFIG_DIR/rift.toml"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Rift Node Installer               ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    check_service_manager
    detect_arch
    detect_os_version
    install_dependencies
    create_directories
    download_binary
    install_service
    configure_node
    start_service
    print_summary
}

main "$@"
