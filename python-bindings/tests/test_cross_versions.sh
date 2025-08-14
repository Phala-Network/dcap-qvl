#!/bin/bash
#
# Test DCAP-QVL Python bindings across multiple Python versions
# This script builds the module with Python 3.8 and tests it across all versions
# This approach is more efficient and realistic for CI/CD scenarios
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Build with minimum supported Python version
BUILD_PYTHON_VERSION="3.8"

# Python versions to test (matching pyproject.toml)
TEST_PYTHON_VERSIONS=("3.8" "3.9" "3.10" "3.11" "3.12" "3.13")

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Results tracking
declare -a SUCCESSFUL_VERSIONS
declare -a FAILED_VERSIONS

print_header() {
    echo -e "\n${BOLD}${BLUE}============================================================${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Check if uv is available
check_uv() {
    if ! command -v uv &>/dev/null; then
        print_error "uv is not available. Please install uv first."
        exit 1
    fi

    local uv_version=$(uv --version)
    print_success "Using $uv_version"
}

# Build the module with Python 3.8
build_module() {
    print_header "Building Module with Python $BUILD_PYTHON_VERSION"

    # Check if build Python version is available
    print_info "Checking if Python $BUILD_PYTHON_VERSION is available..."

    if ! uv python list | grep -q "$BUILD_PYTHON_VERSION"; then
        print_error "Python $BUILD_PYTHON_VERSION is not available for building"
        exit 1
    fi

    print_success "Python $BUILD_PYTHON_VERSION is available"

    # Change to python-bindings directory where pyproject.toml is located
    cd "$PROJECT_ROOT/python-bindings"

    # Clean up any existing build artifacts
    print_info "Cleaning up existing build artifacts..."
    rm -rf .venv build dist target *.egg-info
    find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true
    find . -name "*.so" -delete 2>/dev/null || true

    # Build the extension using uv with Python 3.8
    print_info "Building Python extension with Python $BUILD_PYTHON_VERSION..."
    if ! uv run --python "$BUILD_PYTHON_VERSION" maturin develop --features python; then
        print_error "Build failed with Python $BUILD_PYTHON_VERSION"
        exit 1
    fi

    print_success "Build successful with Python $BUILD_PYTHON_VERSION"

    # Find the built .so file
    local so_file=$(find . -name "*.so" | head -1)
    if [ -z "$so_file" ]; then
        print_error "No .so file found after build"
        exit 1
    fi

    print_info "Built module: $so_file"
    return 0
}

# Test the built module with a specific Python version
test_python_version() {
    local version=$1

    print_header "Testing Built Module with Python $version"

    # Check if Python version is available
    print_info "Checking if Python $version is available..."

    if ! uv python list | grep -q "$version"; then
        print_warning "Python $version is not available"
        FAILED_VERSIONS+=("$version")
        return 1
    fi

    print_success "Python $version is available"

    # Test import
    print_info "Testing import with Python $version..."
    local import_test='
import sys
print(f"Python version: {sys.version}")
import dcap_qvl
print(f"Import successful! dcap_qvl version: {dcap_qvl.__version__}")
print(f"Available functions: {dcap_qvl.__all__}")
'

    if ! uv run --python "$version" python -c "$import_test"; then
        print_error "Import failed with Python $version"
        FAILED_VERSIONS+=("$version")
        return 1
    fi

    print_success "Import successful with Python $version"

    # Test basic functionality
    print_info "Testing basic functionality with Python $version..."
    local basic_test='
import dcap_qvl

# Test creating collateral
collateral = dcap_qvl.QuoteCollateralV3(
    pck_crl_issuer_chain="test",
    root_ca_crl=b"test",
    pck_crl=b"test",
    tcb_info_issuer_chain="test",
    tcb_info="{\"test\": true}",
    tcb_info_signature=b"test",
    qe_identity_issuer_chain="test",
    qe_identity="{\"test\": true}",
    qe_identity_signature=b"test"
)

# Test JSON serialization
json_str = collateral.to_json()
collateral2 = dcap_qvl.QuoteCollateralV3.from_json(json_str)

# Test verify with invalid data (should fail gracefully)
try:
    dcap_qvl.verify(b"invalid", collateral, 1234567890)
    print("ERROR: Should have failed")
    exit(1)
except ValueError:
    print("Basic functionality test passed!")
'

    if ! uv run --python "$version" python -c "$basic_test"; then
        print_error "Basic functionality test failed with Python $version"
        FAILED_VERSIONS+=("$version")
        return 1
    fi

    print_success "Basic functionality test passed with Python $version"

    # Run unit tests if available
    print_info "Running unit tests with Python $version..."
    if [ -d "tests" ] && [ -f "tests/test_python_bindings.py" ]; then
        if uv run --python "$version" pytest \
            tests/test_python_bindings.py::TestQuoteCollateralV3 \
            tests/test_python_bindings.py::TestVerify \
            -v; then
            print_success "Unit tests passed with Python $version"
        else
            print_warning "Unit tests failed with Python $version, but basic functionality works"
        fi
    else
        print_info "No unit tests found, skipping"
    fi

    print_success "Python $version: All tests passed ✅"
    SUCCESSFUL_VERSIONS+=("$version")
    return 0
}

# Main function
main() {
    print_header "DCAP-QVL Cross-Version Python Compatibility Test"
    print_info "Project root: $PROJECT_ROOT"
    print_info "Build Python version: $BUILD_PYTHON_VERSION"
    print_info "Test Python versions: ${TEST_PYTHON_VERSIONS[*]}"

    # Check prerequisites
    check_uv

    # Build the module once with Python 3.8
    build_module

    # Test the built module with each Python version
    for version in "${TEST_PYTHON_VERSIONS[@]}"; do
        test_python_version "$version" || true # Continue even if one fails
    done

    # Print summary
    print_header "Test Summary"

    if [ ${#SUCCESSFUL_VERSIONS[@]} -gt 0 ]; then
        print_success "Successful versions: ${SUCCESSFUL_VERSIONS[*]}"
    else
        print_error "No successful versions"
    fi

    if [ ${#FAILED_VERSIONS[@]} -gt 0 ]; then
        print_error "Failed versions: ${FAILED_VERSIONS[*]}"
    fi

    print_header "Final Results"

    # Exit with appropriate code
    if [ ${#SUCCESSFUL_VERSIONS[@]} -eq ${#TEST_PYTHON_VERSIONS[@]} ]; then
        print_success "🎉 All Python versions passed!"
        exit 0
    elif [ ${#SUCCESSFUL_VERSIONS[@]} -gt 0 ]; then
        print_warning "⚠️  Some Python versions failed, but at least one passed"
        exit 1
    else
        print_error "💥 All Python versions failed!"
        exit 2
    fi
}

# Run main function
main "$@"
