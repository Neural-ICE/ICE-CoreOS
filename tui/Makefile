.PHONY: build clean run check install

# Default target
TARGET = aarch64-unknown-linux-gnu
BINARY = neuralice-tui
INSTALL_DIR = ../ansible/roles/neuralice/files/tui

build:
	cargo build --release

# Cross-compile for ARM64 (if running on x86_64)
build-arm64:
	cross build --release --target $(TARGET)

check:
	cargo check
	cargo clippy -- -W clippy::pedantic

run:
	NEURALICE_VERSION=dev cargo run

# Install binary to Ansible role
install: build
	mkdir -p $(INSTALL_DIR)
	cp target/release/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	chmod +x $(INSTALL_DIR)/$(BINARY)

# Install ARM64 binary (for x86_64 host)
install-arm64: build-arm64
	mkdir -p $(INSTALL_DIR)
	cp target/$(TARGET)/release/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	chmod +x $(INSTALL_DIR)/$(BINARY)

clean:
	cargo clean

# Show binary size
size: build
	ls -lah target/release/$(BINARY)
	strip target/release/$(BINARY) -o target/release/$(BINARY)-stripped
	ls -lah target/release/$(BINARY)-stripped
