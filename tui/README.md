# Neural-ICE TUI (Rust)

Terminal User Interface dashboard for Neural-ICE AI appliances, built with Ratatui.

## Features

- **Cyberpunk-themed UI** with ASCII art logo and neon color palette
- **Real-time system monitoring**: GPU (temp, utilization, VRAM), network, uptime
- **License status** with expiry tracking
- **QR code** for quick device access URL (using `tui-qrcode`)
- **Responsive layout**: Full mode (80+ cols) with QR, compact mode for narrow terminals
- **Visual feedback**: Flash effect on refresh, timestamp display
- **Help screen** (`?`) with keyboard shortcuts
- Settings menu and diagnostics screen

## Screenshots

```
 _   _                       _      ___  ____ _____
| \ | | ___ _   _ _ __ __ _| |    |_ _|/ ___| ____|
|  \| |/ _ \ | | | '__/ _' | |     | || |   |  _|
| |\  |  __/ |_| | | | (_| | |     | || |___| |___
|_| \_|\___|\__,_|_|  \__,_|_|    |___|\____|_____|
              -- Keep your neurons cool --
<=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=->

  | SYSTEM STATUS                    ████████████
    Status: [**] ONLINE              ██        ██
    License: [*] Active -> 2025-12   ██  ████  ██
                                     ██  ████  ██
  | NETWORK                          ██        ██
    Interface: Ethernet enp1s0       ████████████
    IP: 192.168.178.66                 [QR CODE]

  | HARDWARE
    GPU: NVIDIA GB10 (128GB) | 42C | 15%
    Uptime: 2d 5h 30m

<=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=->
  [Enter] Settings   [R] Refresh   [D] Diagnostics   [?] Help
  Neural-ICE v0.11.0 (5s ago)
```

## Building

### Prerequisites

- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- For cross-compilation: `cargo install cross`

### Build Commands

```bash
# Build release binary
make build

# Check code
make check

# Run locally (dev mode)
make run

# Install to Ansible role
make install
```

### Cross-compilation (x86_64 → ARM64)

```bash
# Install cross
cargo install cross

# Build for ARM64
make build-arm64

# Install ARM64 binary
make install-arm64
```

## Binary Size

The release binary is **~645KB** (vs ~4MB for the Go version), thanks to:
- `opt-level = "z"` (size optimization)
- `lto = true` (link-time optimization)
- `panic = "abort"` (no unwinding)
- `strip = true` (remove symbols)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEURALICE_VERSION` | Version to display | `dev` |

## Architecture

```
src/
├── main.rs           # Entry point, terminal setup
├── app.rs            # Application state, event handling, Mode enum
├── system/           # System info collection
│   ├── mod.rs        # SystemInfo struct
│   ├── network.rs    # Network info (nmcli, ip)
│   ├── gpu.rs        # GpuMetrics (nvidia-smi: temp, mem, util)
│   └── license.rs    # License validation status
└── ui/               # User interface (Ratatui widgets)
    ├── mod.rs        # Screen dispatcher
    ├── dashboard.rs  # Main dashboard view
    ├── diagnostics.rs # Detailed system info
    ├── help.rs       # Help popup overlay
    ├── settings.rs   # Settings menu
    ├── theme.rs      # Cyberpunk color palette (THEME static)
    └── widgets.rs    # QrCodePanel widget
```

## Keybindings

### Global
- `?` - Toggle help screen

### Dashboard
- `Enter` - Open settings menu
- `R` - Refresh system info
- `D` - Diagnostics screen
- `Q` / `Esc` - Quit

### Settings Menu
- `↑`/`↓` or `K`/`J` - Navigate
- `Enter` - Select item
- `Esc` - Back to dashboard
- `Q` - Quit

### Diagnostics
- `R` - Refresh
- `Esc` - Back to dashboard
- `Q` - Quit

## UX Features

| Feature | Description |
|---------|-------------|
| **Responsive layout** | Auto-switches between full (QR + side-by-side) and compact mode |
| **Refresh flash** | Green "[Updated]" indicator for 300ms after refresh |
| **Timestamp** | Shows "(5s ago)" or "(2m ago)" since last refresh |
| **GPU metrics** | Temperature, utilization %, memory usage |
| **Help overlay** | Popup with all keybindings |
| **Vim navigation** | J/K keys work alongside arrows |

## Dependencies

- `ratatui` 0.29 - TUI framework
- `crossterm` 0.28 - Terminal backend
- `tui-qrcode` 0.1 - QR code widget
- `qrcode` 0.14 - QR generation
- `anyhow` - Error handling

## Migration from Go

This Rust implementation replaces the Go + Bubbletea version:

| Aspect | Go | Rust |
|--------|-----|------|
| Binary size | 3.8 MB | **645 KB** (6x smaller) |
| Framework | Bubbletea | Ratatui |
| Startup time | ~50ms | ~10ms |
| Memory usage | ~8 MB | ~2 MB |
