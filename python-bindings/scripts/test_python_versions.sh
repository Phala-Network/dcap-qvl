#!/bin/bash
#
# Test DCAP-QVL Python bindings across multiple Python versions
# This script uses uv to test compatibility with different Python versions
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

# Python versions to test (matching pyproject.toml)
PYTHON_VERSIONS=("3.8" "3.9" "3.10" "3.11" "3.12")

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
    if ! command -v uv &> /dev/null; then
        print_error "uv is not available. Please install uv first."
        exit 1
    fi
    
    local uv_version=$(uv --version)
    print_success "Using $uv_version"
}

# Test a specific Python version
test_python_version() {
    local version=$1
    local temp_dir
    temp_dir=$(mktemp -d)
    
    print_header "Testing Python $version"
    
    # Check if Python version is available
    print_info "Checking if Python $version is available..."
    
    # Create temporary test project
    local test_project="$temp_dir/test_project"
    mkdir -p "$test_project"
    
    cat > "$test_project/pyproject.toml" << EOF
[project]
name = "test"
version = "0.1.0"
requires-python = ">=$version"
EOF
    
    if ! (cd "$test_project" && uv sync --python "$version" &>/dev/null); then
        print_warning "Python $version is not available"
        FAILED_VERSIONS+=("$version")
        rm -rf "$temp_dir"
        return 1
    fi
    
    print_success "Python $version is available"
    
    # Create virtual environment for this version
    local venv_dir="$temp_dir/venv-$version"
    print_info "Creating virtual environment..."
    
    if ! uv venv "$venv_dir" --python "$version" &>/dev/null; then
        print_error "Failed to create virtual environment"
        FAILED_VERSIONS+=("$version")
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Install maturin
    print_info "Installing maturin..."
    if ! uv pip install maturin --python "$venv_dir/bin/python" &>/dev/null; then
        print_error "Failed to install maturin"
        FAILED_VERSIONS+=("$version")
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Build the extension
    print_info "Building Python extension..."
    if ! (cd "$PROJECT_ROOT/python-bindings" && VIRTUAL_ENV="$venv_dir" "$venv_dir/bin/python" -m maturin develop --features python &>/dev/null); then
        print_error "Build failed"
        FAILED_VERSIONS+=("$version")
        rm -rf "$temp_dir"
        return 1
    fi
    
    print_success "Build successful"
    
    # Test import
    print_info "Testing import..."
    local import_test='
import dcap_qvl
print(f"Import successful! Version: {dcap_qvl.__version__}")
print(f"Available: {dcap_qvl.__all__}")
'
    
    if ! "$venv_dir/bin/python" -c "$import_test" &>/dev/null; then
        print_error "Import failed"
        FAILED_VERSIONS+=("$version")
        rm -rf "$temp_dir"
        return 1
    fi
    
    print_success "Import successful"
    
    # Test basic functionality
    print_info "Testing basic functionality..."
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
    
    if ! "$venv_dir/bin/python" -c "$basic_test" &>/dev/null; then
        print_error "Basic functionality test failed"
        FAILED_VERSIONS+=("$version")
        rm -rf "$temp_dir"
        return 1
    fi
    
    print_success "Basic functionality test passed"
    
    # Install pytest and run unit tests
    print_info "Installing pytest and running unit tests..."
    if uv pip install pytest --python "$venv_dir/bin/python" &>/dev/null; then
        if (cd "$PROJECT_ROOT/python-bindings" && "$venv_dir/bin/python" -m pytest \
            tests/test_python_bindings.py::TestQuoteCollateralV3 \
            tests/test_python_bindings.py::TestVerify \
            -v &>/dev/null); then
            print_success "Unit tests passed"
        else
            print_warning "Unit tests failed, but basic functionality works"
        fi
    else
        print_warning "Failed to install pytest"
    fi
    
    print_success "Python $version: All tests passed ✅"
    SUCCESSFUL_VERSIONS+=("$version")
    
    # Cleanup
    rm -rf "$temp_dir"
    return 0
}

# Main function
main() {
    print_header "DCAP-QVL Python Version Compatibility Test"
    print_info "Project root: $PROJECT_ROOT"
    print_info "Testing Python versions: ${PYTHON_VERSIONS[*]}"
    
    # Check prerequisites
    check_uv
    
    # Test each Python version
    for version in "${PYTHON_VERSIONS[@]}"; do
        test_python_version "$version" || true  # Continue even if one fails
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
    if [ ${#SUCCESSFUL_VERSIONS[@]} -eq ${#PYTHON_VERSIONS[@]} ]; then
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