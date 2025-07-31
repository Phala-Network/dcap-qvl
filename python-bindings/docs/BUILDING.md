# Building Wheels

This document describes how to build wheels for multiple platforms using maturin's cross-compilation capabilities with optional Zig support.

## Quick Start

Build for the current platform:
```bash
./scripts/build_wheels.sh
```

Build for multiple platforms:
```bash
./scripts/build_wheels.sh "linux-x86_64 linux-aarch64 windows-x64"
```

Using the Python script directly:
```bash
python3 scripts/build_wheels.py --platforms linux-x86_64 windows-x64 macos-x86_64
```

Using Zig for cross-compilation (recommended):
```bash
python3 scripts/build_wheels.py --platforms linux-x86_64 linux-aarch64 --zig --install-targets
```

## Supported Platforms

| Platform | Target Triple | Notes |
|----------|---------------|-------|
| `linux-x86_64` | `x86_64-unknown-linux-gnu` | Most common Linux |
| `linux-aarch64` | `aarch64-unknown-linux-gnu` | ARM64 Linux |
| `linux-i686` | `i686-unknown-linux-gnu` | 32-bit Linux |
| `windows-x64` | `x86_64-pc-windows-msvc` | 64-bit Windows |
| `windows-x86` | `i686-pc-windows-msvc` | 32-bit Windows |
| `macos-x86_64` | `x86_64-apple-darwin` | Intel Mac |
| `macos-aarch64` | `aarch64-apple-darwin` | Apple Silicon Mac |

## Prerequisites

1. **Rust toolchain** with cross-compilation targets:
   ```bash
   # Install additional targets (automatically installed with --install-targets)
   rustup target add x86_64-unknown-linux-gnu
   rustup target add aarch64-unknown-linux-gnu
   rustup target add x86_64-pc-windows-msvc
   rustup target add x86_64-apple-darwin
   rustup target add aarch64-apple-darwin
   ```

2. **Maturin**:
   ```bash
   pip install maturin
   ```

3. **Zig (recommended for cross-compilation)**:
   ```bash
   # Install Zig for easy cross-compilation
   curl -L https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz | tar -xJ
   sudo mv zig-linux-x86_64-0.13.0 /opt/zig
   sudo ln -sf /opt/zig/zig /usr/local/bin/zig
   ```

4. **Platform-specific tools (without Zig)**:
   - **Linux cross-compilation**: Install `gcc-multilib`, `gcc-aarch64-linux-gnu`
   - **Windows cross-compilation**: May require `mingw-w64`
   - **macOS cross-compilation**: Requires macOS SDK (works best on macOS)

## Build Script Options

### Python Script (`build_wheels.py`)

```bash
python3 scripts/build_wheels.py [OPTIONS]

Options:
  --platforms PLATFORM [PLATFORM ...]   Platforms to build for
  --output-dir DIR                       Output directory (default: ../target/wheels)
  --clean                               Clean output directory first
  --install-targets                     Install required Rust targets
  --zig                                 Use Zig for cross-compilation
  -h, --help                           Show help message
```

### Shell Script (`build_wheels.sh`)

```bash
./scripts/build_wheels.sh [PLATFORMS] [OUTPUT_DIR]

Arguments:
  PLATFORMS    Space-separated platform names (default: linux-x86_64)
  OUTPUT_DIR   Output directory (default: ../target/wheels)
```

## Examples

Build for Linux only:
```bash
python3 scripts/build_wheels.py --platforms linux-x86_64
```

Build for all platforms:
```bash
python3 scripts/build_wheels.py \
  --platforms linux-x86_64 linux-aarch64 windows-x64 macos-x86_64 macos-aarch64 \
  --install-targets \
  --clean
```

Build with custom output directory:
```bash
python3 scripts/build_wheels.py \
  --platforms linux-x86_64 windows-x64 \
  --output-dir ./dist
```

Build with Zig cross-compilation:
```bash
python3 scripts/build_wheels.py \
  --platforms linux-x86_64 linux-aarch64 \
  --zig \
  --install-targets \
  --clean
```

## Troubleshooting

### Cross-compilation Issues

1. **Missing target**: Install with `rustup target add <target>` or use `--install-targets`
2. **Linker errors**: Use `--zig` flag for easier cross-compilation
3. **Traditional toolchain**: Install appropriate cross-compilation toolchain (gcc, mingw-w64)
4. **Windows builds on Linux**: May need `wine` for testing (Zig simplifies this)

### Platform-Specific Notes

- **Linux**: Uses manylinux compatibility by default
- **Windows**: Requires MSVC toolchain or mingw-w64
- **macOS**: Cross-compilation from Linux has limitations

### Common Errors

1. **"linker not found"**: Install cross-compilation toolchain
2. **"target not found"**: Run with `--install-targets` flag
3. **"maturin not found"**: Install with `pip install maturin`

## Integration with CI/CD

The build scripts are designed to work with GitHub Actions. See `.github/workflows/python-wheels.yml` for the complete CI/CD setup.

Local testing before CI:
```bash
# Test the same platforms as CI
python3 scripts/build_wheels.py \
  --platforms linux-x86_64 windows-x64 macos-x86_64 \
  --install-targets
```