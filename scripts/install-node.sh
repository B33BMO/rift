#!/bin/bash
#
# Rift Node Installer
#
# This script installs the Rift mesh VPN client on Linux systems.
# Requires: root privileges, systemd
#
# Usage:
#   curl -fsSL https://rift-vpn.example.com/install-node.sh | sudo bash
#   # or
#   sudo ./install-node.sh
#
# Options:
#   --beacon ADDRESS    Set beacon server address (default: prompt)
#   --name NAME         Set node name (default: hostname)
#   --no-start          Don't start the service after install
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rift"
SYSTEMD_DIR="/etc/systemd/system"
RUN_DIR="/var/run/rift"
LIB_DIR="/var/lib/rift"
GITHUB_REPO="rift-vpn/rift"

# Parse arguments
BEACON_ADDR=""
NODE_NAME=""
NO_START=false

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
        log_error "This script must be run as root"
        exit 1
    fi
}

check_systemd() {
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        exit 1
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

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $OS_VERSION"
}

install_dependencies() {
    log_info "Checking dependencies..."

    # Check for TUN support
    if [[ ! -c /dev/net/tun ]]; then
        log_warn "/dev/net/tun not found, creating..."
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 666 /dev/net/tun
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

    # For now, check if binary exists locally (built from source)
    if [[ -f "./target/release/rift-node" ]]; then
        cp ./target/release/rift-node "$INSTALL_DIR/rift-node"
        log_success "Installed from local build"
    else
        # TODO: Download from GitHub releases
        log_error "Binary not found. Please build from source:"
        echo "  git clone https://github.com/$GITHUB_REPO"
        echo "  cd rift && cargo build --release"
        echo "  sudo ./scripts/install-node.sh"
        exit 1
    fi

    chmod 755 "$INSTALL_DIR/rift-node"
    log_success "Binary installed to $INSTALL_DIR/rift-node"
}

install_systemd_service() {
    log_info "Installing systemd service..."

    cat > "$SYSTEMD_DIR/rift-node.service" << 'EOF'
[Unit]
Description=Rift Mesh VPN Node
Documentation=https://github.com/rift-vpn/rift
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

configure_node() {
    if [[ -f "$CONFIG_DIR/rift.toml" ]]; then
        log_warn "Config file already exists, skipping configuration"
        return
    fi

    log_info "Configuring node..."

    # Get node name
    if [[ -z "$NODE_NAME" ]]; then
        NODE_NAME=$(hostname)
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

start_service() {
    if [[ "$NO_START" == "true" ]]; then
        log_info "Skipping service start (--no-start)"
        return
    fi

    log_info "Starting rift-node service..."
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

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       Rift Node Installation Complete     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo "Useful commands:"
    echo "  systemctl status rift-node    - Check status"
    echo "  journalctl -fu rift-node      - View logs"
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
    check_systemd
    detect_arch
    detect_os
    install_dependencies
    create_directories
    download_binary
    install_systemd_service
    configure_node
    start_service
    print_summary
}

main "$@"
