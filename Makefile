# Rift Mesh VPN - Build and Install
#
# Usage:
#   make build          - Build all binaries (debug)
#   make release        - Build optimized binaries
#   make install-node   - Install rift-node (requires sudo)
#   make install-beacon - Install beacon server (requires sudo)
#   make install        - Install both
#   make uninstall      - Remove all installed files

CARGO := cargo
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
SYSCONFDIR := /etc/rift
SYSTEMDDIR := /etc/systemd/system
RUNDIR := /var/run/rift
LIBDIR := /var/lib/rift

.PHONY: all build release clean install install-node install-beacon uninstall test

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test

clean:
	$(CARGO) clean

# Install rift-node client
install-node: release
	@echo "Installing rift-node..."
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -d $(DESTDIR)$(RUNDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 target/release/rift-node $(DESTDIR)$(BINDIR)/rift-node
	install -m 644 rift-node/rift-node.service $(DESTDIR)$(SYSTEMDDIR)/rift-node.service
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/rift.toml ]; then \
		echo "Creating default config..."; \
		$(DESTDIR)$(BINDIR)/rift-node init -n "$$(hostname)" -b "beacon.example.com:7770" -c $(DESTDIR)$(SYSCONFDIR)/rift.toml 2>/dev/null || true; \
	fi
	@echo ""
	@echo "rift-node installed!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit /etc/rift/rift.toml with your beacon address"
	@echo "  2. systemctl daemon-reload"
	@echo "  3. systemctl enable --now rift-node"
	@echo ""

# Install beacon server
install-beacon: release
	@echo "Installing beacon..."
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -d $(DESTDIR)$(RUNDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 target/release/beacon $(DESTDIR)$(BINDIR)/beacon
	install -m 644 beacon/beacon.service $(DESTDIR)$(SYSTEMDDIR)/beacon.service
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/beacon.toml ]; then \
		echo "Creating default config..."; \
		$(DESTDIR)$(BINDIR)/beacon --init -c $(DESTDIR)$(SYSCONFDIR)/beacon.toml 2>/dev/null || true; \
	fi
	@echo ""
	@echo "beacon installed!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit /etc/rift/beacon.toml if needed"
	@echo "  2. Open firewall ports: 7770/udp (control), 7771/udp (relay)"
	@echo "  3. systemctl daemon-reload"
	@echo "  4. systemctl enable --now beacon"
	@echo ""

# Install CLI tool
install-cli: release
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/rift $(DESTDIR)$(BINDIR)/rift

# Install everything
install: install-beacon install-node install-cli

# Uninstall
uninstall:
	@echo "Stopping services..."
	-systemctl stop rift-node 2>/dev/null || true
	-systemctl stop beacon 2>/dev/null || true
	-systemctl disable rift-node 2>/dev/null || true
	-systemctl disable beacon 2>/dev/null || true
	@echo "Removing files..."
	rm -f $(DESTDIR)$(BINDIR)/rift-node
	rm -f $(DESTDIR)$(BINDIR)/beacon
	rm -f $(DESTDIR)$(BINDIR)/rift
	rm -f $(DESTDIR)$(SYSTEMDDIR)/rift-node.service
	rm -f $(DESTDIR)$(SYSTEMDDIR)/beacon.service
	@echo "Reloading systemd..."
	-systemctl daemon-reload 2>/dev/null || true
	@echo ""
	@echo "Uninstalled. Config files in /etc/rift/ were preserved."
	@echo "Remove manually with: rm -rf /etc/rift"

# Interactive installers (run after 'make release')
.PHONY: run-installer-node run-installer-beacon

run-installer-node: release
	@echo "Running rift-node installer..."
	sudo ./scripts/install-node.sh

run-installer-beacon: release
	@echo "Running beacon installer..."
	sudo ./scripts/install-beacon.sh

# Development helpers
.PHONY: dev run-node run-beacon

dev:
	$(CARGO) build
	@echo ""
	@echo "Debug binaries built:"
	@echo "  ./target/debug/rift-node"
	@echo "  ./target/debug/beacon"
	@echo "  ./target/debug/rift"

run-node:
	$(CARGO) run --bin rift-node -- run --foreground

run-beacon:
	$(CARGO) run --bin beacon

# Show line counts
.PHONY: loc
loc:
	@echo "Lines of Rust code:"
	@find . -name "*.rs" -not -path "./target/*" | xargs wc -l | tail -1

# Format and lint
.PHONY: fmt clippy check

fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy -- -D warnings

check: fmt clippy test
	@echo "All checks passed!"

# Release builds
.PHONY: dist dist-all dist-upload

dist:
	./scripts/build-release.sh

dist-all:
	./scripts/build-release.sh --all

dist-upload:
	./scripts/build-release.sh --upload
