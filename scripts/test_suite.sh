#!/bin/bash
# DCAP Quote Verification Test Suite
# Usage: ./scripts/test_suite.sh [rust|python|wasm|all]

set -e

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# Constants
readonly SAMPLES_DIR="test_data/samples"
readonly CERTS_DIR="test_data/certs"
readonly RUST_VERIFY_CLI="./cli/target/release/verify_sample"
readonly PYTHON_VERIFY_CLI="python3 ./python-bindings/verify_sample.py"
readonly WASM_VERIFY_CLI="node ./verify_sample.js"

print_box() {
	local color=$1
	local text=$2
	echo -e "${color}╔══════════════════════════════════════════════════════════╗${NC}"
	printf "${color}║%-58s║${NC}\n" "$(printf "%*s" $(((58 + ${#text}) / 2)) "$text")"
	echo -e "${color}╚══════════════════════════════════════════════════════════╝${NC}"
}

print_separator() {
	local text=$1
	echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
	printf "${CYAN}%*s${NC}\n" $(((60 + ${#text}) / 2)) "$text"
	echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

get_category() {
	local name=$1
	case $name in
	valid_*) echo "Valid Quotes" ;;
	debug_*) echo "Debug Mode" ;;
	*version*) echo "Version Errors" ;;
	*key_type*) echo "Key Type Errors" ;;
	*cert*) echo "Certificate Errors" ;;
	*tcb*) echo "TCB Errors" ;;
	*signature* | *sig*) echo "Signature Errors" ;;
	*fmspc*) echo "FMSPC Errors" ;;
	*decode* | *truncated* | *invalid*) echo "Decode Errors" ;;
	*) echo "Other" ;;
	esac
}

build_rust_tools() {
	if [ ! -f "$RUST_VERIFY_CLI" ]; then
		echo "  Building Rust CLI tools..."
		(cd cli && cargo build --release --bin verify_sample --bin generate_all_samples --quiet 2>&1 | grep -v "warning:") || true
		echo -e "  ${GREEN}✓${NC} Rust CLI tools built"
	else
		echo -e "  ${GREEN}✓${NC} Rust CLI tools already built"
	fi
}

build_python_binding() {
	echo "  Building Python binding..."
	(cd python-bindings && pip install -e . --break-system-packages --quiet 2>&1 | grep -vE "WARNING:|DEPRECATION:") || true
	echo -e "  ${GREEN}✓${NC} Python binding built"
	[ -f "./cli/target/release/generate_all_samples" ] || build_rust_tools
}

check_wasm_opt_version() {
	local min_version=123

	if ! command -v wasm-opt &> /dev/null; then
		echo -e "  ${RED}✗${NC} wasm-opt not found"
		echo "  Please install Binaryen from: https://github.com/WebAssembly/binaryen/releases"
		exit 1
	fi

	local version=$(wasm-opt --version 2>&1 | grep -oP 'version \K[0-9]+' | head -1)
	if [ -z "$version" ]; then
		version=$(wasm-opt --version 2>&1 | grep -oP 'wasm-opt version \K[0-9]+' | head -1)
	fi

	if [ -z "$version" ]; then
		echo -e "  ${YELLOW}⚠${NC} Could not detect wasm-opt version"
	elif [ "$version" -lt "$min_version" ]; then
		echo -e "  ${RED}✗${NC} wasm-opt version $version is too old (minimum: $min_version)"
		echo ""
		echo "  This will cause 'WebAssembly.Table.grow() failed' errors."
		echo "  See: https://github.com/wasm-bindgen/wasm-bindgen/issues/4528"
		echo ""
		echo "  To fix, update wasm-opt:"
		echo "    wget https://github.com/WebAssembly/binaryen/releases/download/version_$min_version/binaryen-version_$min_version-x86_64-linux.tar.gz"
		echo "    tar xzf binaryen-version_$min_version-x86_64-linux.tar.gz"
		echo "    sudo cp binaryen-version_$min_version/bin/wasm-opt /usr/local/bin/"
		echo ""
		exit 1
	else
		echo -e "  ${GREEN}✓${NC} wasm-opt version $version"
	fi
}

build_wasm_binding() {
	check_wasm_opt_version

	if [ ! -d "pkg/node" ] || [ ! -f "pkg/node/dcap-qvl-node.js" ]; then
		echo "  Building WASM binding for Node.js..."
		make build_node_pkg 2>&1 | grep -v "warning:" || true
		echo -e "  ${GREEN}✓${NC} WASM binding built"
	else
		echo -e "  ${GREEN}✓${NC} WASM binding already built"
	fi
	[ -f "./cli/target/release/generate_all_samples" ] || build_rust_tools
}

ensure_certificates() {
	if [ ! -d "$CERTS_DIR" ] || [ ! -f "$CERTS_DIR/root_ca.der" ]; then
		echo "  Generating test certificates..."
		./scripts/generate_test_certs.sh >/dev/null 2>&1
		echo -e "  ${GREEN}✓${NC} Test certificates generated"
	else
		echo -e "  ${GREEN}✓${NC} Certificates found"
	fi
}

ensure_samples() {
	if [ ! -d "$SAMPLES_DIR" ] || [ -z "$(ls -A "$SAMPLES_DIR" 2>/dev/null)" ]; then
		echo "  Running sample generator..."
		./cli/target/release/generate_all_samples
		echo -e "  ${GREEN}✓${NC} Test samples generated"
	else
		local count=$(($(find "$SAMPLES_DIR" -maxdepth 1 -type d | wc -l) - 1))
		echo -e "  ${GREEN}✓${NC} Found $count existing samples"
	fi
}

run_single_test() {
	local sample_dir=$1
	local verify_cli=$2

	local sample_name=$(basename "$sample_dir")
	local quote_file="$sample_dir/quote.bin"
	local collateral_file="$sample_dir/collateral.json"
	local expected_file="$sample_dir/expected.json"

	# Validate required files
	for file in "$quote_file" "$collateral_file" "$expected_file"; do
		if [ ! -f "$file" ]; then
			echo -e "${YELLOW}⚠ SKIP${NC} $sample_name (missing $(basename "$file"))"
			return 1
		fi
	done

	# Parse expected results
	local should_succeed=$(jq -r '.should_succeed' "$expected_file" 2>/dev/null || echo "false")
	local expected_error=$(jq -r '.expected_error // ""' "$expected_file" 2>/dev/null)
	local description=$(jq -r '.description // ""' "$expected_file" 2>/dev/null)

	# Run verification
	local output exit_code
	set +e
	output=$($verify_cli "$quote_file" "$collateral_file" "$CERTS_DIR/root_ca.der" 2>&1)
	exit_code=$?
	set -e

	# Determine test result
	local status result
	if [ "$should_succeed" = "true" ]; then
		if [ $exit_code -eq 0 ]; then
			status="${GREEN}✓ PASS${NC}"
			result="pass"
		else
			status="${RED}✗ FAIL${NC}"
			result="fail"
		fi
	else
		if [ $exit_code -ne 0 ]; then
			if [ -n "$expected_error" ] && echo "$output" | grep -q "$expected_error"; then
				status="${GREEN}✓ PASS${NC}"
				result="pass"
			else
				status="${YELLOW}⚠ WARN${NC}"
				result="warn"
			fi
		else
			status="${RED}✗ FAIL${NC}"
			result="fail"
		fi
	fi

	# Print result to stderr so it shows up immediately
	printf "  %-40s %b\n" "$sample_name" "$status" >&2

	# Print details for failures and warnings
	if [ "$result" != "pass" ]; then
		[ -n "$description" ] && echo -e "    ${CYAN}Desc:${NC} $description" >&2
		case "$result" in
		fail)
			[ "$should_succeed" = "true" ] && echo -e "    ${CYAN}Error:${NC} $(echo "$output" | head -n 1)" >&2
			[ "$should_succeed" = "false" ] && [ $exit_code -eq 0 ] && echo -e "    ${CYAN}Error:${NC} Expected failure but succeeded" >&2
			;;
		warn)
			echo -e "    ${CYAN}Expected:${NC} $expected_error" >&2
			echo -e "    ${CYAN}Got:${NC} $(echo "$output" | head -n 1)" >&2
			;;
		esac
	fi

	# Return result for statistics to stdout
	echo "$result:$(get_category "$sample_name")"
}

run_test_suite() {
	local verify_cli=$1
	local test_name=$2

	print_box "$CYAN" "DCAP Quote Verification Test Suite"
	echo ""
	echo -e "${BLUE}Configuration:${NC}"
	echo "  Test Mode: $test_name"
	echo "  Verify CLI: $verify_cli"
	echo "  Samples directory: $SAMPLES_DIR"
	echo ""

	# Setup
	echo -e "${BLUE}━━━ Step 1: Building tools ━━━${NC}"
	if [ "$test_name" = "Python Binding" ]; then
		build_python_binding
	elif [ "$test_name" = "WASM Binding" ]; then
		build_wasm_binding
	else
		build_rust_tools
	fi
	echo ""

	echo -e "${BLUE}━━━ Step 2: Checking test certificates ━━━${NC}"
	ensure_certificates
	echo ""

	echo -e "${BLUE}━━━ Step 3: Generating test samples ━━━${NC}"
	ensure_samples
	echo ""

	# Run tests
	echo -e "${BLUE}━━━ Step 4: Running verification tests ━━━${NC}"
	echo ""

	local total=0 passed=0 failed=0 warned=0
	local valid_quotes=0 debug_mode=0 version_errors=0 key_type_errors=0
	local certificate_errors=0 tcb_errors=0 signature_errors=0 fmspc_errors=0
	local decode_errors=0 other=0

	for sample_dir in "$SAMPLES_DIR"/*; do
		[ -d "$sample_dir" ] || continue

		local result
		if result=$(run_single_test "$sample_dir" "$verify_cli"); then
			total=$((total + 1))

			IFS=':' read -r outcome category <<<"$result"
			case "$outcome" in
			pass) passed=$((passed + 1)) ;;
			fail) failed=$((failed + 1)) ;;
			warn)
				warned=$((warned + 1))
				passed=$((passed + 1))
				;;
			esac

			# Update category stats
			case "$category" in
			"Valid Quotes") valid_quotes=$((valid_quotes + 1)) ;;
			"Debug Mode") debug_mode=$((debug_mode + 1)) ;;
			"Version Errors") version_errors=$((version_errors + 1)) ;;
			"Key Type Errors") key_type_errors=$((key_type_errors + 1)) ;;
			"Certificate Errors") certificate_errors=$((certificate_errors + 1)) ;;
			"TCB Errors") tcb_errors=$((tcb_errors + 1)) ;;
			"Signature Errors") signature_errors=$((signature_errors + 1)) ;;
			"FMSPC Errors") fmspc_errors=$((fmspc_errors + 1)) ;;
			"Decode Errors") decode_errors=$((decode_errors + 1)) ;;
			"Other") other=$((other + 1)) ;;
			esac
		fi
	done

	# Print results
	echo ""
	echo -e "${BLUE}━━━ Test Results by Category ━━━${NC}"
	printf "  %-20s: %s\n" "Valid Quotes" "$valid_quotes/$valid_quotes passed"
	printf "  %-20s: %s\n" "Debug Mode" "$debug_mode/$debug_mode passed"
	printf "  %-20s: %s\n" "Version Errors" "$version_errors/$version_errors passed"
	printf "  %-20s: %s\n" "Key Type Errors" "$key_type_errors/$key_type_errors passed"
	printf "  %-20s: %s\n" "Certificate Errors" "$certificate_errors/$certificate_errors passed"
	printf "  %-20s: %s\n" "TCB Errors" "$tcb_errors/$tcb_errors passed"
	printf "  %-20s: %s\n" "Signature Errors" "$signature_errors/$signature_errors passed"
	printf "  %-20s: %s\n" "FMSPC Errors" "$fmspc_errors/$fmspc_errors passed"
	printf "  %-20s: %s\n" "Decode Errors" "$decode_errors/$decode_errors passed"
	printf "  %-20s: %s\n" "Other" "$other/$other passed"

	echo ""
	print_box "$CYAN" "Test Summary"
	echo ""
	echo "  Total Tests:    $total"
	echo -e "  ${GREEN}Passed:${NC}         $passed"
	[ $warned -gt 0 ] && echo -e "  ${YELLOW}Warnings:${NC}       $warned"
	echo -e "  ${RED}Failed:${NC}         $failed"

	if [ $total -gt 0 ]; then
		local pass_rate=$(echo "scale=1; $passed * 100 / $total" | bc)
		echo ""
		echo -e "  Pass Rate:      ${pass_rate}%"
	fi

	echo ""

	# Final status
	if [ $failed -eq 0 ]; then
		print_box "$GREEN" "All tests passed! 🎉"
		return 0
	else
		print_box "$RED" "Some tests failed! ❌"
		return 1
	fi
}

run_all_tests() {
	print_box "$MAGENTA" "Testing All Versions"
	echo ""

	print_separator "Testing Rust CLI"
	echo ""
	"$0" rust
	local rust_exit=$?

	echo ""
	echo ""

	print_separator "Testing Python Binding"
	echo ""
	"$0" python
	local python_exit=$?

	echo ""
	echo ""

	print_separator "Testing WASM Binding"
	echo ""
	"$0" wasm
	local wasm_exit=$?

	echo ""
	echo ""

	# Overall summary
	print_box "$MAGENTA" "Overall Summary"
	echo ""

	[ $rust_exit -eq 0 ] && echo -e "  ${GREEN}✓${NC} Rust CLI:       All tests passed" || echo -e "  ${RED}✗${NC} Rust CLI:       Some tests failed"
	[ $python_exit -eq 0 ] && echo -e "  ${GREEN}✓${NC} Python Binding: All tests passed" || echo -e "  ${RED}✗${NC} Python Binding: Some tests failed"
	[ $wasm_exit -eq 0 ] && echo -e "  ${GREEN}✓${NC} WASM Binding:   All tests passed" || echo -e "  ${RED}✗${NC} WASM Binding:   Some tests failed"

	echo ""

	if [ $rust_exit -eq 0 ] && [ $python_exit -eq 0 ] && [ $wasm_exit -eq 0 ]; then
		print_box "$GREEN" "All tests passed in all versions! 🎉"
		exit 0
	else
		print_box "$RED" "Some tests failed! ❌"
		exit 1
	fi
}

main() {
	local test_mode="${1:-rust}"

	if [[ ! "$test_mode" =~ ^(rust|python|wasm|all)$ ]]; then
		echo -e "${RED}Error: Invalid test mode '$test_mode'${NC}" >&2
		echo "Usage: $0 [rust|python|wasm|all]" >&2
		exit 1
	fi

	case "$test_mode" in
	all)
		run_all_tests
		;;
	python)
		run_test_suite "$PYTHON_VERIFY_CLI" "Python Binding"
		;;
	wasm)
		run_test_suite "$WASM_VERIFY_CLI" "WASM Binding"
		;;
	rust)
		run_test_suite "$RUST_VERIFY_CLI" "Rust CLI"
		;;
	esac
}

main "$@"
