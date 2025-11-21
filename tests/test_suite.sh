#!/bin/bash
# DCAP Quote Verification Test Suite
# Usage: ./tests/test_suite.sh [rust|python|wasm|js|all]
# Note: Can be run from any directory

set -e

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# Constants - make them work from any directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly SAMPLES_DIR="$PROJECT_ROOT/test_data/samples"
readonly CERTS_DIR="$PROJECT_ROOT/test_data/certs"
readonly RUST_TEST_CASE_CLI="$PROJECT_ROOT/cli/target/release/test_case"
readonly PYTHON_TEST_CASE_CLI="python3 $PROJECT_ROOT/python-bindings/test_case.py"
readonly WASM_TEST_CASE_CLI="node $PROJECT_ROOT/tests/test_case.js"
readonly JS_TEST_CASE_CLI="node --no-warnings $PROJECT_ROOT/dcap-qvl-js/test_case.js"

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
	if [ ! -f "$RUST_TEST_CASE_CLI" ] || [ ! -f "$PROJECT_ROOT/cli/target/release/generate_all_samples" ]; then
		echo "  Building Rust CLI tools..."
		(cd "$PROJECT_ROOT/cli" && cargo build --release --bin test_case --bin generate_all_samples --quiet 2>&1 | grep -v "warning:") || true
		echo -e "  ${GREEN}✓${NC} Rust CLI tools built"
	else
		echo -e "  ${GREEN}✓${NC} Rust CLI tools already built"
	fi
}

build_python_binding() {
	echo "  Building Python binding..."
	(cd "$PROJECT_ROOT/python-bindings" && pip install -e . --break-system-packages --quiet 2>&1 | grep -vE "WARNING:|DEPRECATION:") || true
	echo -e "  ${GREEN}✓${NC} Python binding built"
	[ -f "$PROJECT_ROOT/cli/target/release/generate_all_samples" ] || build_rust_tools
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
	[ -f "$PROJECT_ROOT/cli/target/release/generate_all_samples" ] || build_rust_tools
}

build_js_binding() {
	echo "  Building Pure JS binding..."
	if [ ! -d "$PROJECT_ROOT/dcap-qvl-js/node_modules" ]; then
		(cd "$PROJECT_ROOT/dcap-qvl-js" && npm install --quiet 2>&1 | grep -vE "npm WARN") || true
	fi
	echo -e "  ${GREEN}✓${NC} Pure JS binding ready"
	[ -f "$PROJECT_ROOT/cli/target/release/generate_all_samples" ] || build_rust_tools
}

ensure_certificates() {
	if [ ! -d "$CERTS_DIR" ] || [ ! -f "$CERTS_DIR/root_ca.der" ]; then
		echo "  Generating test certificates..."
		"$SCRIPT_DIR/generate_test_certs.sh" >/dev/null 2>&1
		echo -e "  ${GREEN}✓${NC} Test certificates generated"
	else
		echo -e "  ${GREEN}✓${NC} Certificates found"
	fi
}

ensure_samples() {
	if [ ! -d "$SAMPLES_DIR" ] || [ -z "$(ls -A "$SAMPLES_DIR" 2>/dev/null)" ]; then
		echo "  Running sample generator..."
		"$PROJECT_ROOT/cli/target/release/generate_all_samples"
		echo -e "  ${GREEN}✓${NC} Test samples generated"
	else
		local count=$(($(find "$SAMPLES_DIR" -maxdepth 1 -type d | wc -l) - 1))
		echo -e "  ${GREEN}✓${NC} Found $count existing samples"
	fi
}

run_single_test() {
	local sample_dir=$1
	local test_case_cli=$2

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
	output=$($test_case_cli verify "$quote_file" "$collateral_file" "$CERTS_DIR/root_ca.der" 2>&1)
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

run_get_collateral_test() {
	local test_case_cli=$1
	local test_name=$2
	local pccs_arg=$3
	local quote_file="$PROJECT_ROOT/sample/tdx_quote"

	if [ ! -f "$quote_file" ]; then
		echo -e "  ${YELLOW}⚠${NC} Skipping get-collateral test - no TDX quote available"
		return 0
	fi

	echo "  Testing get-collateral for $test_name, pccs arg: ${pccs_arg:-none}"

	local cmd="$test_case_cli"
	local cmd_args="get-collateral $pccs_arg $quote_file"

	# Run the test with timeout
	local output
	local exit_code
	if output=$(timeout 30 $cmd $cmd_args 2>&1); then
		exit_code=0
	else
		exit_code=$?
	fi

	if [ $exit_code -eq 0 ]; then
		# Parse JSON and validate each field
		local pck_crl_issuer_chain_length=$(echo "$output" | jq -r '.pck_crl_issuer_chain | length' 2>/dev/null || echo "0")
		local root_ca_crl_length=$(echo "$output" | jq -r '.root_ca_crl | length' 2>/dev/null || echo "0")
		local pck_crl_length=$(echo "$output" | jq -r '.pck_crl | length' 2>/dev/null || echo "0")
		local tcb_info_issuer_chain_length=$(echo "$output" | jq -r '.tcb_info_issuer_chain | length' 2>/dev/null || echo "0")
		local tcb_info=$(echo "$output" | jq -r '.tcb_info' 2>/dev/null || echo "")
		local tcb_info_signature_length=$(echo "$output" | jq -r '.tcb_info_signature | length' 2>/dev/null || echo "0")
		local qe_identity_issuer_chain_length=$(echo "$output" | jq -r '.qe_identity_issuer_chain | length' 2>/dev/null || echo "0")
		local qe_identity=$(echo "$output" | jq -r '.qe_identity' 2>/dev/null || echo "")
		local qe_identity_signature_length=$(echo "$output" | jq -r '.qe_identity_signature | length' 2>/dev/null || echo "0")

		# Check all required fields are non-empty
		if [ "$pck_crl_issuer_chain_length" -eq 0 ]; then
			echo "  Validation failed: pck_crl_issuer_chain is empty" >&2
			return 1
		fi

		if [ "$root_ca_crl_length" -eq 0 ]; then
			echo "  Validation failed: root_ca_crl is empty" >&2
			return 1
		fi

		if [ "$pck_crl_length" -eq 0 ]; then
			echo "  Validation failed: pck_crl is empty" >&2
			return 1
		fi

		if [ "$tcb_info_issuer_chain_length" -eq 0 ]; then
			echo "  Validation failed: tcb_info_issuer_chain is empty" >&2
			return 1
		fi

		if [ -z "$tcb_info" ] || [ "$tcb_info" = "null" ]; then
			echo "  Validation failed: tcb_info is missing or null" >&2
			return 1
		fi

		if [ "$tcb_info_signature_length" -eq 0 ]; then
			echo "  Validation failed: tcb_info_signature is empty" >&2
			return 1
		fi

		if [ "$qe_identity_issuer_chain_length" -eq 0 ]; then
			echo "  Validation failed: qe_identity_issuer_chain is empty" >&2
			return 1
		fi

		if [ -z "$qe_identity" ] || [ "$qe_identity" = "null" ]; then
			echo "  Validation failed: qe_identity is missing or null" >&2
			return 1
		fi

		if [ "$qe_identity_signature_length" -eq 0 ]; then
			echo "  Validation failed: qe_identity_signature is empty" >&2
			return 1
		fi

		# Check TCB info format (tcb_info is already a JSON string)
		local tcb_id=$(echo "$tcb_info" | jq -r '.id' 2>/dev/null || echo "")
		local tcb_version=$(echo "$tcb_info" | jq -r '.version' 2>/dev/null || echo "")
		if [ "$tcb_id" != "TDX" ] || [ -z "$tcb_version" ] || [ "$tcb_version" = "null" ] || [ "$tcb_version" -eq 0 ]; then
			echo "  Validation failed: Invalid TCB info format (id='$tcb_id', version='$tcb_version')" >&2
			return 1
		fi

		# Check QE identity format (qe_identity is already a JSON string)
		local qe_id=$(echo "$qe_identity" | jq -r '.id' 2>/dev/null || echo "")
		local qe_version=$(echo "$qe_identity" | jq -r '.version' 2>/dev/null || echo "")
		if [ -z "$qe_id" ] || [ "$qe_id" = "null" ] || [ -z "$qe_version" ] || [ "$qe_version" = "null" ] || [ "$qe_version" -eq 0 ]; then
			echo "  Validation failed: Invalid QE identity format (id='$qe_id', version='$qe_version')" >&2
			return 1
		fi

		# Detailed format validation for each field type
		local validation_passed=true

		# 1. Check certificate chains (should start with -----BEGIN CERTIFICATE-----)
		local pck_crl_chain=$(echo "$output" | jq -r '.pck_crl_issuer_chain')
		if [[ "$pck_crl_chain" != "-----BEGIN CERTIFICATE-----"* ]]; then
			echo "  Validation failed: pck_crl_issuer_chain is not a valid certificate format" >&2
			validation_passed=false
		fi

		local tcb_info_chain=$(echo "$output" | jq -r '.tcb_info_issuer_chain')
		if [[ "$tcb_info_chain" != "-----BEGIN CERTIFICATE-----"* ]]; then
			echo "  Validation failed: tcb_info_issuer_chain is not a valid certificate format" >&2
			validation_passed=false
		fi

		local qe_identity_chain=$(echo "$output" | jq -r '.qe_identity_issuer_chain')
		if [[ "$qe_identity_chain" != "-----BEGIN CERTIFICATE-----"* ]]; then
			echo "  Validation failed: qe_identity_issuer_chain is not a valid certificate format" >&2
			validation_passed=false
		fi

		# 2. Check JSON strings (should be parseable JSON)
		local tcb_info_json=$(echo "$output" | jq -r '.tcb_info')
		if ! echo "$tcb_info_json" | jq empty 2>/dev/null; then
			echo "  Validation failed: tcb_info is not valid JSON" >&2
			validation_passed=false
		fi

		local qe_identity_json=$(echo "$output" | jq -r '.qe_identity')
		if ! echo "$qe_identity_json" | jq empty 2>/dev/null; then
			echo "  Validation failed: qe_identity is not valid JSON" >&2
			validation_passed=false
		fi

		# 3. Check hex strings (should contain only hex characters)
		local pck_crl_hex=$(echo "$output" | jq -r '.pck_crl')
		if ! [[ "$pck_crl_hex" =~ ^[0-9a-fA-F]+$ ]]; then
			echo "  Validation failed: pck_crl is not a valid hex string" >&2
			validation_passed=false
		fi

		local root_ca_crl_hex=$(echo "$output" | jq -r '.root_ca_crl')
		if ! [[ "$root_ca_crl_hex" =~ ^[0-9a-fA-F]+$ ]]; then
			echo "  Validation failed: root_ca_crl is not a valid hex string" >&2
			validation_passed=false
		fi

		local tcb_sig_hex=$(echo "$output" | jq -r '.tcb_info_signature')
		if ! [[ "$tcb_sig_hex" =~ ^[0-9a-fA-F]+$ ]]; then
			echo "  Validation failed: tcb_info_signature is not a valid hex string" >&2
			validation_passed=false
		fi

		local qe_sig_hex=$(echo "$output" | jq -r '.qe_identity_signature')
		if ! [[ "$qe_sig_hex" =~ ^[0-9a-fA-F]+$ ]]; then
			echo "  Validation failed: qe_identity_signature is not a valid hex string" >&2
			validation_passed=false
		fi

		# 4. Check hex string lengths for signatures (64 bytes = 128 hex chars for ECDSA)
		if [ "$tcb_info_signature_length" -ne 128 ]; then
			echo "  Validation failed: tcb_info_signature has unexpected length ($tcb_info_signature_length, expected 128)" >&2
			validation_passed=false
		fi

		if [ "$qe_identity_signature_length" -ne 128 ]; then
			echo "  Validation failed: qe_identity_signature has unexpected length ($qe_identity_signature_length, expected 128)" >&2
			validation_passed=false
		fi

		[ "$validation_passed" = true ] && return 0 || return 1

		return 0
	else
		# Check if output contains an error message
		if echo "$output" | jq -e '.error' > /dev/null 2>&1; then
			local error_msg=$(echo "$output" | jq -r '.error' 2>/dev/null)
			echo "  Get collateral failed: $error_msg" >&2
		else
			echo "$output" >&2
		fi
		return 1
	fi
}

run_test_suite() {
	local test_case_cli=$1
	local test_name=$2

	print_box "$CYAN" "DCAP Quote Verification Test Suite"
	echo ""
	echo -e "${BLUE}Configuration:${NC}"
	echo "  Test Mode: $test_name"
	echo "  Test CLI: $test_case_cli"
	echo "  Samples directory: $SAMPLES_DIR"
	echo ""

	# Setup
	echo -e "${BLUE}━━━ Step 1: Building tools ━━━${NC}"
	if [ "$test_name" = "Python Binding" ]; then
		build_python_binding
	elif [ "$test_name" = "WASM Binding" ]; then
		build_wasm_binding
	elif [ "$test_name" = "Pure JS Binding" ]; then
		build_js_binding
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
		if result=$(run_single_test "$sample_dir" "$test_case_cli"); then
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

	# Run get-collateral test
	echo ""
	echo -e "${BLUE}━━━ Step 5: Running get-collateral tests ━━━${NC}"
	echo ""

	run_get_collateral_test "$test_case_cli" "$test_name" ""
	run_get_collateral_test "$test_case_cli" "$test_name" "--pccs-url https://pccs.phala.network/tdx/certification/v4"
	local collateral_exit=$?

	if [ $collateral_exit -eq 0 ]; then
		echo -e "  ${GREEN}✓${NC} Get collateral test with real TDX quote passed"
	else
		echo -e "  ${RED}✗${NC} Get collateral test with real TDX quote failed"
		failed=$((failed + 1))
		total=$((total + 1))
	fi

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

	print_separator "Testing Pure JS Binding"
	echo ""
	"$0" js
	local js_exit=$?

	echo ""
	echo ""

	# Overall summary
	print_box "$MAGENTA" "Overall Summary"
	echo ""

	[ $rust_exit -eq 0 ] && echo -e "  ${GREEN}✓${NC} Rust CLI:       All tests passed" || echo -e "  ${RED}✗${NC} Rust CLI:       Some tests failed"
	[ $python_exit -eq 0 ] && echo -e "  ${GREEN}✓${NC} Python Binding: All tests passed" || echo -e "  ${RED}✗${NC} Python Binding: Some tests failed"
	[ $wasm_exit -eq 0 ] && echo -e "  ${GREEN}✓${NC} WASM Binding:   All tests passed" || echo -e "  ${RED}✗${NC} WASM Binding:   Some tests failed"
	[ $js_exit -eq 0 ] && echo -e "  ${GREEN}✓${NC} Pure JS Binding: All tests passed" || echo -e "  ${RED}✗${NC} Pure JS Binding: Some tests failed"

	echo ""

	if [ $rust_exit -eq 0 ] && [ $python_exit -eq 0 ] && [ $wasm_exit -eq 0 ] && [ $js_exit -eq 0 ]; then
		print_box "$GREEN" "All tests passed in all versions! 🎉"
		exit 0
	else
		print_box "$RED" "Some tests failed! ❌"
		exit 1
	fi
}

main() {
	local test_mode="${1:-all}"

	if [[ ! "$test_mode" =~ ^(rust|python|wasm|js|all)$ ]]; then
		echo -e "${RED}Error: Invalid test mode '$test_mode'${NC}" >&2
		echo "Usage: $0 [rust|python|wasm|js|all]" >&2
		exit 1
	fi

	case "$test_mode" in
	all)
		run_all_tests
		;;
	python)
		run_test_suite "$PYTHON_TEST_CASE_CLI" "Python Binding"
		;;
	wasm)
		run_test_suite "$WASM_TEST_CASE_CLI" "WASM Binding"
		;;
	js)
		run_test_suite "$JS_TEST_CASE_CLI" "Pure JS Binding"
		;;
	rust)
		run_test_suite "$RUST_TEST_CASE_CLI" "Rust CLI"
		;;
	esac
}

main "$@"
