#!/bin/bash
#
# Rift Beacon Server Installer
#
# This script installs the Rift beacon (coordination server) on Linux systems.
# Requires: root privileges, systemd
#
# Usage:
#   curl -fsSL https://rift-vpn.example.com/install-beacon.sh | sudo bash
#   # or
#   sudo ./install-beacon.sh
#
# Options:
#   --port PORT         Set control port (default: 7770)
#   --relay-port PORT   Set relay port (default: 7771)
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
CONTROL_PORT="7770"
RELAY_PORT="7771"
NO_START=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            CONTROL_PORT="$2"
            shift 2
            ;;
        --relay-port)
            RELAY_PORT="$2"
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
    log_info "Downloading beacon..."

    # For now, check if binary exists locally (built from source)
    if [[ -f "./target/release/beacon" ]]; then
        cp ./target/release/beacon "$INSTALL_DIR/beacon"
        log_success "Installed from local build"
    else
        # TODO: Download from GitHub releases
        log_error "Binary not found. Please build from source:"
        echo "  git clone https://github.com/$GITHUB_REPO"
        echo "  cd rift && cargo build --release"
        echo "  sudo ./scripts/install-beacon.sh"
        exit 1
    fi

    chmod 755 "$INSTALL_DIR/beacon"
    log_success "Binary installed to $INSTALL_DIR/beacon"
}

install_systemd_service() {
    log_info "Installing systemd service..."

    cat > "$SYSTEMD_DIR/beacon.service" << 'EOF'
[Unit]
Description=Rift Beacon Server
Documentation=https://github.com/rift-vpn/rift
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/beacon --config /etc/rift/beacon.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

# State directory
StateDirectory=rift
ConfigurationDirectory=rift
RuntimeDirectory=rift

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=beacon

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service installed"
}

configure_beacon() {
    if [[ -f "$CONFIG_DIR/beacon.toml" ]]; then
        log_warn "Config file already exists, skipping configuration"
        return
    fi

    log_info "Configuring beacon..."

    # Generate config
    "$INSTALL_DIR/beacon" --init -c "$CONFIG_DIR/beacon.toml" 2>/dev/null || {
        # Fallback: create config manually
        cat > "$CONFIG_DIR/beacon.toml" << EOF
# Rift Beacon Server Configuration

[server]
# Address to listen on for control connections
listen_addr = "0.0.0.0:${CONTROL_PORT}"

# Port for relay traffic
relay_port = ${RELAY_PORT}

# Maximum number of registered nodes
max_nodes = 1000

# Node timeout in seconds (remove inactive nodes)
node_timeout_secs = 300

[logging]
# Log level: error, warn, info, debug, trace
level = "info"
EOF
    }

    chmod 600 "$CONFIG_DIR/beacon.toml"
    log_success "Configuration saved to $CONFIG_DIR/beacon.toml"
}

configure_firewall() {
    log_info "Checking firewall..."

    # Try to detect and configure firewall
    if command -v ufw &> /dev/null; then
        log_info "UFW detected, adding rules..."
        ufw allow ${CONTROL_PORT}/udp comment "Rift beacon control" 2>/dev/null || true
        ufw allow ${RELAY_PORT}/udp comment "Rift beacon relay" 2>/dev/null || true
        log_success "UFW rules added"
    elif command -v firewall-cmd &> /dev/null; then
        log_info "firewalld detected, adding rules..."
        firewall-cmd --permanent --add-port=${CONTROL_PORT}/udp 2>/dev/null || true
        firewall-cmd --permanent --add-port=${RELAY_PORT}/udp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_success "firewalld rules added"
    else
        log_warn "No supported firewall detected"
        echo ""
        echo "Please manually open these UDP ports:"
        echo "  - ${CONTROL_PORT}/udp (control)"
        echo "  - ${RELAY_PORT}/udp (relay)"
        echo ""
    fi
}

start_service() {
    if [[ "$NO_START" == "true" ]]; then
        log_info "Skipping service start (--no-start)"
        return
    fi

    log_info "Starting beacon service..."
    systemctl enable beacon
    systemctl start beacon

    sleep 2

    if systemctl is-active --quiet beacon; then
        log_success "beacon is running"
    else
        log_error "beacon failed to start. Check: journalctl -u beacon"
        exit 1
    fi
}

print_summary() {
    # Get external IP for display
    EXTERNAL_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "<your-server-ip>")

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      Rift Beacon Installation Complete    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo "Useful commands:"
    echo "  systemctl status beacon     - Check status"
    echo "  journalctl -fu beacon       - View logs"
    echo ""
    echo "Config file: $CONFIG_DIR/beacon.toml"
    echo ""
    echo -e "${YELLOW}Important:${NC}"
    echo "  Ensure these UDP ports are open in your firewall:"
    echo "    - ${CONTROL_PORT}/udp (control)"
    echo "    - ${RELAY_PORT}/udp (relay)"
    echo ""
    echo "Clients can connect using:"
    echo "  --beacon ${EXTERNAL_IP}:${CONTROL_PORT}"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        Rift Beacon Installer              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    check_systemd
    detect_arch
    detect_os
    create_directories
    download_binary
    install_systemd_service
    configure_beacon
    configure_firewall
    start_service
    print_summary
}

main "$@"
