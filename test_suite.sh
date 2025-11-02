#!/bin/bash
# DCAP Quote Verification Test Suite - Root Directory Wrapper
# Usage: ./test_suite.sh [rust|python|wasm|all]

# Execute the actual test suite from the tests directory
exec "$(dirname "$0")/tests/test_suite.sh" "$@"