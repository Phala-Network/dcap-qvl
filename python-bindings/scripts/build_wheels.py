#!/usr/bin/env python3
"""
Cross-platform wheel building script using maturin.
Builds wheels for multiple platforms and architectures.
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path
from typing import List, Dict, Optional

# Ensure UTF-8 encoding on Windows
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())

# Platform configurations
PLATFORMS = {
    # Linux platforms (manylinux)
    "linux-x86_64": {
        "target": "x86_64-unknown-linux-gnu",
        "platform_tag": "manylinux_2_17_x86_64"
    },
    "linux-aarch64": {
        "target": "aarch64-unknown-linux-gnu",
        "platform_tag": "manylinux_2_17_aarch64"
    },
    # Linux platforms (musllinux)
    "linux-x86_64-musl": {
        "target": "x86_64-unknown-linux-musl",
        "platform_tag": "musllinux_1_1_x86_64"
    },
    "linux-aarch64-musl": {
        "target": "aarch64-unknown-linux-musl",
        "platform_tag": "musllinux_1_1_aarch64"
    },

    # Windows platforms
    "windows-x64": {
        "target": "x86_64-pc-windows-msvc",
        "platform_tag": "win_amd64"
    },
    "windows-x86": {
        "target": "i686-pc-windows-msvc",
        "platform_tag": "win32"
    },

    # macOS platforms
    "macos-x86_64": {
        "target": "x86_64-apple-darwin",
        "platform_tag": "macosx_10_12_x86_64"
    },
    "macos-aarch64": {
        "target": "aarch64-apple-darwin",
        "platform_tag": "macosx_11_0_arm64"
    },
}


def run_command(cmd: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    if cwd:
        print(f"Working directory: {cwd}")

    # Use UTF-8 encoding on Windows to handle Unicode characters in output
    encoding = "utf-8" if sys.platform == "win32" else None

    # Set environment variables for UTF-8 on Windows
    env = os.environ.copy()
    if sys.platform == "win32":
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding=encoding,
        errors="replace",  # Replace invalid characters instead of failing
        env=env
    )

    if result.stdout:
        print("STDOUT:", result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    return result


def check_prerequisites():
    """Check if required tools are installed."""
    print("Checking prerequisites...")

    # Check maturin
    result = run_command(["maturin", "--version"])
    if result.returncode != 0:
        print("ERROR: maturin not found. Install with: pip install maturin")
        sys.exit(1)

    # Check cargo
    result = run_command(["cargo", "--version"])
    if result.returncode != 0:
        print("ERROR: cargo not found. Install Rust toolchain.")
        sys.exit(1)

    print("* Prerequisites check passed")


def install_rust_targets(platforms: List[str]):
    """Install required Rust targets for cross-compilation."""
    print("Installing Rust targets...")

    targets_to_install = set()
    for platform in platforms:
        if platform in PLATFORMS:
            targets_to_install.add(PLATFORMS[platform]["target"])

    for target in targets_to_install:
        print(f"Installing target: {target}")
        result = run_command(["rustup", "target", "add", target])
        if result.returncode != 0:
            print(f"Warning: Failed to install target {target}")

    print("* Rust targets installation completed")


def build_wheel(platform: str, output_dir: Path, use_zig: bool = False) -> bool:
    """Build a wheel for the specified platform."""
    if platform not in PLATFORMS:
        print(f"ERROR: Unknown platform '{platform}'")
        return False

    config = PLATFORMS[platform]
    target = config["target"]

    print(f"\n=== Building wheel for {platform} ({target}) ===")

    # Prepare maturin command
    cmd = [
        "maturin", "build",
        "--release",
        "--target", target,
        "--out", str(output_dir)
    ]

    # Add interpreter selection
    if platform.startswith("windows"):
        cmd.append("--find-interpreter")
    else:
        cmd.extend(["--interpreter", "python3.7"])

    # Add cross-compilation flags
    if use_zig:
        cmd.append("--zig")

    # Add platform-specific flags
    if platform.startswith("linux"):
        # Use manylinux for Linux builds (PyPI requires manylinux tags)
        # Also build musllinux for Alpine/musl-based distributions
        if platform.endswith("-musl"):
            cmd.extend(["--compatibility", "musllinux_1_1"])
        else:
            cmd.extend(["--compatibility", "manylinux_2_17"])
    elif platform == "windows-x86":
        # 32-bit Windows often has issues, try with minimal features
        cmd.extend(["--no-default-features", "--features", "std,python"])

    # Run the build
    project_root = Path(__file__).parent.parent
    result = run_command(cmd, cwd=project_root)

    if result.returncode == 0:
        print(f"* Successfully built wheel for {platform}")
        return True
    else:
        print(f"* Failed to build wheel for {platform}")
        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Build wheels for multiple platforms")
    parser.add_argument(
        "--platforms",
        nargs="+",
        default=["linux-x86_64"],
        choices=list(PLATFORMS.keys()),
        help="Platforms to build for"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("../target/wheels"),
        help="Output directory for wheels"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean output directory before building"
    )
    parser.add_argument(
        "--install-targets",
        action="store_true",
        help="Install required Rust targets"
    )
    parser.add_argument(
        "--zig",
        action="store_true",
        help="Use Zig for cross-compilation (requires zig to be installed)"
    )

    args = parser.parse_args()

    # Check prerequisites
    check_prerequisites()

    # Create output directory
    output_dir = args.output_dir.resolve()
    if args.clean and output_dir.exists():
        print(f"Cleaning output directory: {output_dir}")
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")

    # Install Rust targets if requested
    if args.install_targets:
        install_rust_targets(args.platforms)

    # Build wheels for each platform
    successful_builds = []
    failed_builds = []

    for platform in args.platforms:
        if build_wheel(platform, output_dir, args.zig):
            successful_builds.append(platform)
        else:
            failed_builds.append(platform)

    # Summary
    print(f"\n=== Build Summary ===")
    print(
        f"Successful builds ({len(successful_builds)}): {', '.join(successful_builds)}")
    if failed_builds:
        print(
            f"Failed builds ({len(failed_builds)}): {', '.join(failed_builds)}")

    print(f"\nWheels output directory: {output_dir}")

    # List generated wheels
    wheels = list(output_dir.glob("*.whl"))
    if wheels:
        print(f"\nGenerated wheels:")
        for wheel in wheels:
            print(f"  - {wheel.name}")

    return len(failed_builds) == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
