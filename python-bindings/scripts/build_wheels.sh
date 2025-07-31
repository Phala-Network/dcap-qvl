#!/bin/bash
# Simple shell script wrapper for building wheels

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building wheels for dcap-qvl..."
echo "Project root: $PROJECT_ROOT"

# Default platforms for local development
DEFAULT_PLATFORMS="linux-x86_64"

# Parse command line arguments
PLATFORMS="${1:-$DEFAULT_PLATFORMS}"
OUTPUT_DIR="${2:-$PROJECT_ROOT/../target/wheels}"

echo "Platforms: $PLATFORMS"
echo "Output directory: $OUTPUT_DIR"

# Run the Python build script
cd "$PROJECT_ROOT"
python3 scripts/build_wheels.py \
    --platforms $PLATFORMS \
    --output-dir "$OUTPUT_DIR" \
    --install-targets

echo "✓ Wheel building completed!"
echo "Check wheels in: $OUTPUT_DIR"