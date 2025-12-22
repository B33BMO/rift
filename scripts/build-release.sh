#!/bin/bash
#
# Build release binaries for all platforms
#
# Usage:
#   ./scripts/build-release.sh           # Build for current platform only
#   ./scripts/build-release.sh --all     # Build for all platforms (requires cross)
#   ./scripts/build-release.sh --upload  # Build and upload to bmo.guru
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

DIST_DIR="./dist"
BINARIES="rift-node beacon rift"

# Parse args
BUILD_ALL=false
UPLOAD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            BUILD_ALL=true
            shift
            ;;
        --upload)
            UPLOAD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log() {
    echo -e "${BLUE}[BUILD]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# Detect current platform
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        darwin) OS="macos" ;;
        linux)  OS="linux" ;;
    esac

    case "$ARCH" in
        x86_64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
    esac

    echo "${OS}-${ARCH}"
}

# Build for a specific target
build_target() {
    local target=$1
    local suffix=$2

    log "Building for $target..."

    if [[ "$target" == *"linux"* ]] && [[ "$(uname -s)" == "Darwin" ]]; then
        # Cross-compile from macOS to Linux
        if ! command -v cross &> /dev/null; then
            echo -e "${YELLOW}[WARN]${NC} 'cross' not installed. Install with: cargo install cross"
            echo "       Skipping $target"
            return
        fi
        cross build --release --target "$target"
    else
        cargo build --release --target "$target"
    fi

    # Copy binaries
    for bin in $BINARIES; do
        local src="target/${target}/release/${bin}"
        local dst="${DIST_DIR}/${bin}-${suffix}"
        if [[ -f "$src" ]]; then
            cp "$src" "$dst"
            chmod +x "$dst"
            success "Built $dst"
        fi
    done
}

# Main
main() {
    log "Preparing dist directory..."
    rm -rf "$DIST_DIR"
    mkdir -p "$DIST_DIR"

    if [[ "$BUILD_ALL" == "true" ]]; then
        log "Building for all platforms..."

        # Define targets
        declare -A TARGETS=(
            ["x86_64-unknown-linux-gnu"]="linux-x86_64"
            ["aarch64-unknown-linux-gnu"]="linux-aarch64"
            ["x86_64-apple-darwin"]="macos-x86_64"
            ["aarch64-apple-darwin"]="macos-aarch64"
        )

        # Add targets
        for target in "${!TARGETS[@]}"; do
            rustup target add "$target" 2>/dev/null || true
        done

        # Build each target
        for target in "${!TARGETS[@]}"; do
            build_target "$target" "${TARGETS[$target]}"
        done
    else
        # Build for current platform only
        PLATFORM=$(detect_platform)
        log "Building for current platform: $PLATFORM"

        cargo build --release

        for bin in $BINARIES; do
            local src="target/release/${bin}"
            local dst="${DIST_DIR}/${bin}-${PLATFORM}"
            if [[ -f "$src" ]]; then
                cp "$src" "$dst"
                chmod +x "$dst"
                success "Built $dst"
            fi
        done
    fi

    # Generate checksums
    log "Generating checksums..."
    cd "$DIST_DIR"
    if command -v sha256sum &> /dev/null; then
        sha256sum * > SHA256SUMS
    elif command -v shasum &> /dev/null; then
        shasum -a 256 * > SHA256SUMS
    fi
    cd - > /dev/null

    # Upload if requested
    if [[ "$UPLOAD" == "true" ]]; then
        log "Uploading to bmo.guru..."

        BMO_RELEASES="../bmo-guru/public/rift/releases"
        if [[ -d "$BMO_RELEASES" ]] || mkdir -p "$BMO_RELEASES"; then
            cp "$DIST_DIR"/* "$BMO_RELEASES/"
            success "Uploaded to $BMO_RELEASES"
            echo ""
            echo "Don't forget to deploy bmo-guru!"
        else
            echo -e "${YELLOW}[WARN]${NC} Could not find bmo-guru project"
            echo "       Copy files manually from $DIST_DIR"
        fi
    fi

    # Summary
    echo ""
    echo -e "${GREEN}Build complete!${NC}"
    echo ""
    echo "Binaries in $DIST_DIR:"
    ls -la "$DIST_DIR"
}

main "$@"
