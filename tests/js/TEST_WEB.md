# Testing Web WASM Bindings

## Automated Testing

Run the automated test suite:

```bash
# From project root
./tests/test_web.sh

# Or using make
make test_wasm_web
```

This will:
1. Build the web package if needed
2. Start a local HTTP server
3. Run tests in a headless browser (if available)
4. Report test results

## Manual Testing

### Quick Start

1. **Build the web package:**
   ```bash
   make build_web_pkg
   ```

2. **Generate test data** (if not already generated):
   ```bash
   ./tests/test_suite.sh wasm
   ```

3. **Setup test directory:**
   ```bash
   cd tests/js
   ln -sf ../../pkg pkg
   ln -sf ../../test_data test_data
   ```

4. **Start a local web server:**
   ```bash
   python3 -m http.server 8000
   # or use: npx http-server -p 8000
   ```

5. **Open in browser:**
   - Automated tests: http://localhost:8000/verify_quote_web_test.html
   - Single quote test: http://localhost:8000/index.html
