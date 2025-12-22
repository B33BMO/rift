#!/bin/bash
#
# Rift Beacon Server Installer
#
# This script installs the Rift beacon (coordination server) on Linux and macOS.
# Requires: root privileges, systemd (Linux) or launchd (macOS)
#
# Usage:
#   curl -fsSL https://bmo.guru/rift/install-beacon.sh | sudo bash
#   # or
#   sudo ./install-beacon.sh
#
# Options:
#   --port PORT         Set control port (default: 7770)
#   --relay-port PORT   Set relay port (default: 7771)
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
    SERVICE_NAME="com.rift.beacon"
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
CONTROL_PORT="7770"
RELAY_PORT="7771"
NO_START=false
VERSION="latest"

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

    # Check for local build first (development)
    if [[ -f "./target/release/beacon" ]]; then
        cp ./target/release/beacon "$INSTALL_DIR/beacon"
        log_success "Installed from local build"
        chmod 755 "$INSTALL_DIR/beacon"
        return
    fi

    # Determine download URL based on OS
    local BINARY_NAME="beacon-${OS}-${ARCH}"
    local DOWNLOAD_URL

    if [[ "$VERSION" == "latest" ]]; then
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}"
    else
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${BINARY_NAME}"
    fi

    # Try to download
    log_info "Fetching from: $DOWNLOAD_URL"

    if curl -fsSL -o /tmp/beacon "$DOWNLOAD_URL" 2>/dev/null; then
        mv /tmp/beacon "$INSTALL_DIR/beacon"
        log_success "Downloaded from GitHub releases"
    elif curl -fsSL -o /tmp/beacon "${DOWNLOAD_BASE}/${BINARY_NAME}" 2>/dev/null; then
        mv /tmp/beacon "$INSTALL_DIR/beacon"
        log_success "Downloaded from bmo.guru"
    else
        log_error "Failed to download binary."
        echo ""
        echo "Options:"
        echo "  1. Build from source:"
        echo "     git clone https://github.com/$GITHUB_REPO"
        echo "     cd rift && cargo build --release"
        echo "     sudo ./scripts/install-beacon.sh"
        echo ""
        echo "  2. Check releases at: https://github.com/$GITHUB_REPO/releases"
        exit 1
    fi

    chmod 755 "$INSTALL_DIR/beacon"
    log_success "Binary installed to $INSTALL_DIR/beacon"
}

install_service_linux() {
    log_info "Installing systemd service..."

    cat > "$SYSTEMD_DIR/beacon.service" << 'EOF'
[Unit]
Description=Rift Beacon Server
Documentation=https://github.com/bischoffdev/rift
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
        <string>${INSTALL_DIR}/beacon</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/beacon.toml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/usr/local/var/log/beacon.log</string>

    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/beacon.error.log</string>

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

    if [[ "$OS" == "linux" ]]; then
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
    elif [[ "$OS" == "macos" ]]; then
        log_info "macOS firewall: add Beacon to allowed apps in System Preferences > Security"
        log_warn "Or open ports ${CONTROL_PORT}/udp and ${RELAY_PORT}/udp manually"
    fi
}

start_service_linux() {
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

start_service_macos() {
    launchctl load -w "$LAUNCHD_DIR/${SERVICE_NAME}.plist"

    sleep 2

    if launchctl list | grep -q "$SERVICE_NAME"; then
        log_success "beacon is running"
    else
        log_error "beacon failed to start. Check: /usr/local/var/log/beacon.error.log"
        exit 1
    fi
}

start_service() {
    if [[ "$NO_START" == "true" ]]; then
        log_info "Skipping service start (--no-start)"
        return
    fi

    log_info "Starting beacon service..."

    if [[ "$OS" == "linux" ]]; then
        start_service_linux
    elif [[ "$OS" == "macos" ]]; then
        start_service_macos
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
    if [[ "$OS" == "linux" ]]; then
        echo "  systemctl status beacon     - Check status"
        echo "  journalctl -fu beacon       - View logs"
    elif [[ "$OS" == "macos" ]]; then
        echo "  sudo launchctl list | grep beacon   - Check status"
        echo "  tail -f /usr/local/var/log/beacon.log  - View logs"
        echo "  sudo launchctl stop $SERVICE_NAME   - Stop service"
        echo "  sudo launchctl start $SERVICE_NAME  - Start service"
    fi
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
    check_service_manager
    detect_arch
    detect_os_version
    create_directories
    download_binary
    install_service
    configure_beacon
    configure_firewall
    start_service
    print_summary
}

main "$@"
