WASM_PACK = wasm-pack
INSTALL_TOOL = cargo install wasm-pack
BUILD_WEB = $(WASM_PACK) build --release --target web --out-dir pkg/web --out-name dcap-qvl-web -- --features=js
BUILD_NODE = $(WASM_PACK) build --release --target nodejs --out-dir pkg/node --out-name dcap-qvl-node -- --features=js
MIN_WASM_OPT_VERSION = 123

all: install_wasm_tool check_wasm_opt build_web_pkg build_node_pkg

install_wasm_tool:
	@echo "Installing wasm-pack if not already installed..."
	@if ! command -v $(WASM_PACK) >/dev/null 2>&1; then \
		echo "wasm-pack not found, installing..."; \
		$(INSTALL_TOOL); \
	else \
		echo "wasm-pack is already installed."; \
	fi

check_wasm_opt:
	@echo "Checking wasm-opt version..."
	@if ! command -v wasm-opt > /dev/null 2>&1; then \
		echo "ERROR: wasm-opt not found. Please install Binaryen."; \
		echo "Download from: https://github.com/WebAssembly/binaryen/releases"; \
		exit 1; \
	fi
	@WASM_OPT_VERSION=$$(wasm-opt --version 2>&1 | grep -oP 'version \K[0-9]+' | head -1); \
	if [ -z "$$WASM_OPT_VERSION" ]; then \
		WASM_OPT_VERSION=$$(wasm-opt --version 2>&1 | grep -oP 'wasm-opt version \K[0-9]+' | head -1); \
	fi; \
	if [ -z "$$WASM_OPT_VERSION" ]; then \
		echo "WARNING: Could not detect wasm-opt version"; \
	elif [ "$$WASM_OPT_VERSION" -lt $(MIN_WASM_OPT_VERSION) ]; then \
		echo "ERROR: wasm-opt version $$WASM_OPT_VERSION is too old (minimum required: $(MIN_WASM_OPT_VERSION))"; \
		echo ""; \
		echo "This will cause 'WebAssembly.Table.grow() failed' errors."; \
		echo "See: https://github.com/wasm-bindgen/wasm-bindgen/issues/4528"; \
		echo ""; \
		echo "To fix, update wasm-opt:"; \
		echo "  wget https://github.com/WebAssembly/binaryen/releases/download/version_$(MIN_WASM_OPT_VERSION)/binaryen-version_$(MIN_WASM_OPT_VERSION)-x86_64-linux.tar.gz"; \
		echo "  tar xzf binaryen-version_$(MIN_WASM_OPT_VERSION)-x86_64-linux.tar.gz"; \
		echo "  sudo cp binaryen-version_$(MIN_WASM_OPT_VERSION)/bin/wasm-opt /usr/local/bin/"; \
		echo ""; \
		exit 1; \
	else \
		echo "wasm-opt version $$WASM_OPT_VERSION (OK)"; \
	fi

build_web_pkg: install_wasm_tool check_wasm_opt
	@echo "Building for web browsers..."
	$(BUILD_WEB)

build_node_pkg: install_wasm_tool check_wasm_opt
	@echo "Building for Node.js..."
	$(BUILD_NODE)

publish_npm: build_web_pkg build_node_pkg
	@echo "Updating package names..."
	@if command -v jq &> /dev/null; then \
		jq '.name = "@phala/dcap-qvl-web"' pkg/web/package.json > pkg/web/package.json.tmp && mv pkg/web/package.json.tmp pkg/web/package.json; \
		jq '.name = "@phala/dcap-qvl-node"' pkg/node/package.json > pkg/node/package.json.tmp && mv pkg/node/package.json.tmp pkg/node/package.json; \
	else \
		sed -i.bak 's/"name": "dcap-qvl"/"name": "@phala\/dcap-qvl-web"/' pkg/web/package.json && rm pkg/web/package.json.bak; \
		sed -i.bak 's/"name": "dcap-qvl"/"name": "@phala\/dcap-qvl-node"/' pkg/node/package.json && rm pkg/node/package.json.bak; \
	fi
	@echo "Publishing web package to npm..."
	cd pkg/web && npm publish --access public
	@echo "Publishing node package to npm..."
	cd pkg/node && npm publish --access public

clean:
	@echo "Cleaning up..."
	rm -rf pkg

# Python bindings targets
build_python:
	@echo "Building Python bindings..."
	cd python-bindings && uv run maturin develop --features python

test_python:
	@echo "Testing Python bindings..."
	cd python-bindings && uv run python examples/basic_test.py
	@echo "Testing Python bindings across multiple versions..."
	./python-bindings/tests/test_python_versions.sh
	@echo "Testing collateral API..."
	cd python-bindings && uv run python -m pytest tests/test_collateral_api.py -v
	@echo "Testing async collateral functions..."
	cd python-bindings && uv run python tests/test_with_samples.py
	@echo "Testing across Python versions with cross-version script..."
	cd python-bindings && ./tests/test_cross_versions.sh
	@echo "Testing async collateral functions with sample data..."
	cd python-bindings && uv run python tests/test_with_samples.py
	@echo "Running comprehensive async function tests..."
	cd python-bindings && uv run python tests/test_all_async_functions.py

python_clean:
	@echo "Cleaning Python build artifacts..."
	rm -rf target/wheels/
	rm -rf python-bindings/python_version_test_report.json
	find python-bindings -name "*.pyc" -delete
	find python-bindings -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

test_wasm_web:
	@echo "Testing Web WASM bindings..."
	./tests/test_web.sh

test_wasm_node:
	@echo "Testing Node.js WASM bindings..."
	./tests/test_suite.sh wasm

test_wasm: test_wasm_node

.PHONY: all install_wasm_tool check_wasm_opt build_web_pkg build_node_pkg publish_npm clean build_python python_dev test_python test_python_versions test_collateral_api test_cross_versions python_clean test_wasm_web test_wasm_node test_wasm
