# Test the JS bindings

## Verify Quote with Node

```
cd tests/js
node verify_quote_node.js
```

## Verify Quote with Web

```
cd tests/js
ln -sf ../../pkg pkg
ln -sf ../../sample sample
python3 -m http.server 8000
```

Open http://localhost:8000/index.html in browser, and check the console for the result.
