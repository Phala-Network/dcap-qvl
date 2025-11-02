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

### Test Files

- **verify_quote_web_test.html** - Automated test suite
  - Tests multiple quote types (valid, invalid, debug mode, etc.)
  - Shows pass/fail status for each test
  - Reports overall results

- **index.html** - Simple single quote verification
  - Tests one TDX quote
  - Good for debugging

- **get_collateral_web.html** - Collateral fetching test
  - Tests the `js_get_collateral` function

## Requirements

### CORS and Security Headers

Web browsers require specific headers for WASM modules:
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`

The test server automatically sets these headers.

### File Access

The web version needs access to:
- `/pkg/web/dcap-qvl-web.js` - WASM module JS wrapper
- `/pkg/web/dcap-qvl-web_bg.wasm` - WASM binary
- `/test_data/samples/*/quote.bin` - Test quote files
- `/test_data/samples/*/collateral.json` - Collateral files
- `/test_data/certs/root_ca.der` - Test root CA certificate

## Troubleshooting

### WASM module fails to load

**Error:** `Failed to compile wasm module`

**Solution:** Make sure you're using a web server (not `file://` protocol) and the server sets proper CORS headers.

### Tests fail to find files

**Error:** `Failed to fetch /test_data/...`

**Solution:** Ensure symbolic links are created:
```bash
cd tests/js
ln -sf ../../test_data test_data
ln -sf ../../pkg pkg
```

### Table.grow() error

**Error:** `WebAssembly.Table.grow(): failed to grow table`

**Solution:** Update wasm-opt to version 123+:
```bash
wget https://github.com/WebAssembly/binaryen/releases/download/version_123/binaryen-version_123-x86_64-linux.tar.gz
tar xzf binaryen-version_123-x86_64-linux.tar.gz
sudo cp binaryen-version_123/bin/wasm-opt /usr/local/bin/
```

Then rebuild:
```bash
make clean
make build_web_pkg
```

## CI/CD Testing

For automated testing in CI/CD pipelines, use headless browsers:

### Using Playwright

```bash
npm install -D playwright
npx playwright test tests/js/playwright.spec.js
```

### Using Puppeteer

```bash
npm install -D puppeteer
node tests/js/puppeteer-test.js
```

### Using Chromium/Chrome Headless

```bash
chromium-browser --headless --disable-gpu --dump-dom \
  --virtual-time-budget=10000 \
  http://localhost:8000/verify_quote_web_test.html
```

## Expected Results

All tests should pass:
- ✓ Valid SGX v3 quote
- ✓ Valid TDX v4 quote
- ✓ Invalid quote format should fail
- ✓ Truncated quote should fail with proper error
- ✓ Debug mode should be detected

**Pass rate: 100%**
