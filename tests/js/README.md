# Test the JS/WASM bindings

## Automated Testing

### Node.js WASM Tests

From the project root:
```bash
./tests/test_suite.sh wasm
# or
make test_wasm_node
```

### Web WASM Tests

From the project root:
```bash
./tests/test_web.sh
# or
make test_wasm_web
```

See [TEST_WEB.md](TEST_WEB.md) for detailed web testing documentation.

## Manual Testing

### Verify Quote with Node.js

```bash
cd tests/js
node verify_quote_node.js
```

### Verify Quote in Web Browser

```bash
cd tests/js
ln -sf ../../pkg pkg
ln -sf ../../test_data test_data
python3 -m http.server 8000
```

Then open in browser:
- **Automated tests**: http://localhost:8000/verify_quote_web_test.html
- **Single quote test**: http://localhost:8000/index.html
- **Collateral fetch test**: http://localhost:8000/get_collateral_web.html

Check the browser console for results.
