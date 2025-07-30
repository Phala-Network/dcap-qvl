WASM_PACK = wasm-pack
INSTALL_TOOL = cargo install wasm-pack
BUILD_WEB = $(WASM_PACK) build --release --target web --out-dir pkg/web --out-name dcap-qvl-web -- --features=js
BUILD_NODE = $(WASM_PACK) build --release --target nodejs --out-dir pkg/node --out-name dcap-qvl-node -- --features=js

all: install_wasm_tool build_web_pkg build_node_pkg

install_wasm_tool:
	@echo "Installing wasm-pack if not already installed..."
	@if ! command -v $(WASM_PACK) &> /dev/null; then \
		echo "wasm-pack not found, installing..."; \
		$(INSTALL_TOOL); \
	else \
		echo "wasm-pack is already installed."; \
	fi

build_web_pkg: install_wasm_tool
	@echo "Building for web browsers..."
	$(BUILD_WEB)

build_node_pkg: install_wasm_tool
	@echo "Building for Node.js..."
	$(BUILD_NODE)

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
	./python-bindings/scripts/test_python_versions.sh
	@echo "Testing collateral API..."
	cd python-bindings && uv run python -m pytest tests/test_collateral_api.py -v
	@echo "Testing across Python versions with cross-version script..."
	cd python-bindings && ./scripts/test_cross_versions.sh

python_clean:
	@echo "Cleaning Python build artifacts..."
	rm -rf target/wheels/
	rm -rf python-bindings/python_version_test_report.json
	find python-bindings -name "*.pyc" -delete
	find python-bindings -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

.PHONY: all install_wasm_tool build_web_pkg build_node_pkg clean build_python python_dev test_python test_python_versions test_collateral_api test_cross_versions python_clean
